"""Command line interface for ``egyxos``.

The implementation intentionally uses argparse so the base installation has no
runtime dependency. Rich/Typer can be installed by applications that want a
fancier shell, but are not required for safe operation.
"""

import argparse
import json
import os
import shutil
import sys
import subprocess
from pathlib import Path

from . import __version__
from .config import config_path, load_config, write_default_config
from .context import ScanContext
from .errors import EgyxosError
from .integrations import SCANNERS
from .models import Asset, Finding, ScanResult
from .methodology import stage_catalog
from .pipeline import run_pipeline, run_scanner
from .reporting import render, write_report

TOOLS = {
    "subfinder": "Passive subdomain discovery",
    "httpx": "HTTP probing and technology detection",
    "katana": "Web crawling",
    "paramspider": "Archived URL/parameter discovery",
    "arjun": "Hidden HTTP parameter discovery",
    "ffuf": "Web fuzzing (requires an explicit wordlist)",
    "nmap": "Port and service discovery",
    "nuclei": "Template-based vulnerability checks",
    "sqlmap": "SQL injection testing (explicit opt-in only)",
}


def _common(parser):
    parser.add_argument("target", help="Authorized hostname, IP, CIDR, or http(s) URL")
    parser.add_argument("--yes-i-am-authorized", "--yes", "-y", action="store_true",
                        help="Confirm you own or are explicitly authorized to test the target")
    parser.add_argument("--allow-private", "-P", action="store_true",
                        help="Allow private/loopback targets (still requires authorization)")
    parser.add_argument("--timeout", "-x", type=float, default=None, help="Per-tool timeout in seconds")
    parser.add_argument("--threads", "-T", type=int, default=10, help="Concurrent workers (default: 10)")
    parser.add_argument("--rate-limit", "-R", type=float, default=None, help="Requests per second")
    parser.add_argument("--scope-file", "-S", type=Path, help="File containing additional authorized hosts")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress non-result output")
    parser.add_argument("--verbose", "-V", action="store_true", help="Enable verbose progress output")
    parser.add_argument("--no-color", "-C", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--debug", "-D", action="store_true", help="Enable debug diagnostics")
    parser.add_argument("--output", "-o", type=Path, help="Write a report to this file")
    parser.add_argument("--format", "-F", choices=("terminal", "json", "csv", "html", "sarif"),
                        default="terminal", help="Report format (default: terminal)")
    parser.add_argument("--json", action="store_const", const="json", dest="format",
                        help="Shorthand for --format json")
    parser.add_argument("--output-dir", "-O", type=Path, default=None)
    parser.add_argument("--wordlist", "-w", type=Path, help="Wordlist for fuzz")


def build_parser():
    parser = argparse.ArgumentParser(prog="egyxos", description="Safe modular security reconnaissance CLI")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for name, description in (
        ("scan", "Run the conservative recon pipeline"),
        ("recon", "Alias for scan; run the recon pipeline"),
    ):
        command = sub.add_parser(name, help=description)
        _common(command)
        command.add_argument("--include-vuln", "-v", action="store_true", help="Include nuclei checks")
        command.add_argument("--profile", "-M", choices=("passive", "standard", "deep", "active"),
                             default="standard")
        command.add_argument("--only", help="Comma-separated scanner names to run")
        command.add_argument("--exclude", help="Comma-separated scanner names to skip")
        command.add_argument("--sqli", action="store_true", help="Explicitly enable SQLmap checks")
        command.add_argument("--no-subdomains", action="store_true")
        command.add_argument("--no-ports", action="store_true")
        command.add_argument("--no-vuln", action="store_true")
        command.add_argument("--severity", "-L", default="info", help="Minimum severity")
    for name, aliases, description in (
        ("subdomains", ("-d", "-s"), "Discover subdomains with subfinder"),
        ("http", ("-h",), "Probe HTTP services with httpx"),
        ("crawl", ("-c",), "Crawl a target with katana"),
        ("urls", ("-u",), "Discover archived URLs with paramspider"),
        ("params", ("-p",), "Discover hidden parameters with arjun"),
        ("fuzz", ("-f",), "Fuzz a URL with ffuf (requires --wordlist)"),
        ("ports", ("-n",), "Scan services with nmap"),
        ("vuln", ("-v",), "Run nuclei vulnerability templates"),
    ):
        command = sub.add_parser(name, aliases=list(aliases), help=description)
        _common(command)
    sqli = sub.add_parser("sqli", help="Run sqlmap; explicit opt-in is mandatory")
    _common(sqli)
    sqli.add_argument("--i-understand-sqlmap", action="store_true",
                      help="Explicitly opt into sqlmap testing")
    report = sub.add_parser("report", aliases=["-r"], help="Convert a JSON result to a report format")
    report.add_argument("input", type=Path)
    report.add_argument("--format", choices=("terminal", "json", "csv", "html", "sarif"), default="terminal")
    report.add_argument("--output", "-o", type=Path)
    tools = sub.add_parser("tools", aliases=["-t"], help="Manage optional scanner dependencies")
    tools.add_argument("action", choices=("list", "check", "versions"), nargs="?", default="check")
    tools.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    config = sub.add_parser("config", aliases=["-g"], help="Show or initialize configuration")
    config.add_argument("action", choices=("show", "init", "path"), nargs="?", default="show")
    config.add_argument("--path", type=Path)
    sub.add_parser("version", aliases=["-V"], help="Print the Egyxos version")
    methodology = sub.add_parser("methodology", aliases=["-m"], help="Show the modular reconnaissance methodology")
    methodology.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    return parser


def _context(args):
    values = load_config()
    if args.output_dir is not None:
        values["output_dir"] = str(args.output_dir)
    if args.timeout is not None:
        values["timeout"] = args.timeout
    if getattr(args, "wordlist", None):
        values["wordlist"] = str(args.wordlist)
    if getattr(args, "severity", None):
        values["severity"] = args.severity
    if getattr(args, "command", None) == "sqli":
        values["sqlmap_opt_in"] = bool(args.i_understand_sqlmap)
    authorized = bool(args.yes_i_am_authorized or os.environ.get("EGYXOS_AUTHORIZED") == "1")
    return ScanContext(
        args.target, requested_target=args.target, authorized=authorized,
        allow_private=bool(args.allow_private or values.get("allow_private", False)),
        timeout=float(values.get("timeout", 120)),
        output_dir=values.get("output_dir", "egyxos-results"),
        scope_file=getattr(args, "scope_file", None),
        profile=getattr(args, "profile", "standard"),
        severity=getattr(args, "severity", values.get("severity", "info")),
        threads=max(1, getattr(args, "threads", 10)),
        rate_limit=getattr(args, "rate_limit", None),
        config={**values, "progress": not args.quiet and args.format == "terminal",
                "verbose": args.verbose, "no_color": args.no_color},
    )


def _emit(result, args):
    text = render(result, args.format, color=not getattr(args, "no_color", False))
    if args.output:
        write_report(result, args.output, args.format)
        if args.format == "terminal":
            print(f"Report written to {args.output}")
    else:
        print(text)
    return 0


def _report(args):
    input_path = args.input
    if input_path.is_dir():
        candidates = (input_path / "result.json", input_path / "findings.json", input_path / "report.json")
        input_path = next((candidate for candidate in candidates if candidate.exists()), None)
        if input_path is None:
            raise ValueError("Results directory does not contain result.json, findings.json, or report.json.")
    data = json.loads(input_path.read_text(encoding="utf-8"))
    result = ScanResult(
        scanner=data.get("scanner", "imported"),
        target=data.get("target", "unknown"),
        started_at=data.get("started_at", ""),
        finished_at=data.get("finished_at"),
        assets=[Asset(**asset) for asset in data.get("assets", [])],
        findings=[Finding(**finding) for finding in data.get("findings", [])],
        raw_output=data.get("raw_output", ""),
        metadata=data.get("metadata", {}),
        errors=data.get("errors", []),
    )
    _emit(result, args)
    return 1 if result.findings else 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.command = {
        "-d": "subdomains", "-s": "subdomains", "-h": "http",
        "-c": "crawl", "-u": "urls", "-p": "params", "-f": "fuzz",
        "-n": "ports", "-v": "vuln", "-r": "report", "-t": "tools",
        "-g": "config", "-V": "version", "-m": "methodology",
    }.get(args.command, args.command)
    try:
        if args.command == "version":
            print(__version__)
            return 0
        if args.command == "methodology":
            if args.json:
                print(json.dumps(stage_catalog(), indent=2))
            else:
                for stage in stage_catalog():
                    tools = ", ".join(stage["tools"]) or "built-in"
                    suffix = f" [{stage['opt_in']}]" if stage["opt_in"] else ""
                    print(f"{stage['name']:<28} {tools}{suffix}")
            return 0
        if args.command == "tools":
            available = {name: {"description": description, "available": bool(shutil.which(name))}
                         for name, description in TOOLS.items()}
            if args.action == "versions":
                versions = {}
                for name in TOOLS:
                    if shutil.which(name):
                        try:
                            completed = subprocess.run([name, "--version"], capture_output=True,
                                                       text=True, timeout=5, check=False)
                            versions[name] = (completed.stdout or completed.stderr).splitlines()[0][:200]
                        except (OSError, subprocess.TimeoutExpired):
                            versions[name] = "unavailable"
                    else:
                        versions[name] = "missing"
                print(json.dumps(versions, indent=2) if args.json else
                      "\n".join(f"{name:12} {version}" for name, version in versions.items()))
            elif args.action == "list":
                print(json.dumps(TOOLS, indent=2) if args.json else
                      "\n".join(f"{name:12} {description}" for name, description in TOOLS.items()))
            else:
                print(json.dumps(available, indent=2) if args.json else
                      "\n".join(f"{name:12} {'available' if info['available'] else 'missing'} - {info['description']}"
                                for name, info in available.items()))
            return 0
        if args.command == "config":
            path = args.path or config_path()
            if args.action == "init":
                print(write_default_config(path))
            elif args.action == "path":
                print(path)
            else:
                print(json.dumps(load_config(path), indent=2, sort_keys=True))
            return 0
        if args.command == "report":
            return _report(args)
        context = _context(args)
        if args.command in ("scan", "recon"):
            result = run_pipeline(context, include_vuln=args.include_vuln or args.sqli,
                                  only=args.only, exclude=args.exclude,
                                  no_subdomains=args.no_subdomains, no_ports=args.no_ports,
                                  no_vuln=args.no_vuln)
        else:
            scanner_name = {"subdomains": "subfinder"}.get(args.command, args.command)
            result = run_scanner(scanner_name, context)
        return _emit(result, args)
    except (EgyxosError, OSError, ValueError, json.JSONDecodeError) as exc:
        error = exc.as_dict() if isinstance(exc, EgyxosError) else {
            "error": "invalid_request", "message": str(exc), "details": {}
        }
        print(json.dumps(error, indent=2), file=sys.stderr)
        return 2
