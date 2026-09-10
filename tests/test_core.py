import json

import pytest

from egyxos.cli import main
from egyxos.context import ScanContext
from egyxos.errors import AuthorizationError, ScopeError
from egyxos.models import Asset, Finding, ScanResult
from egyxos.reporting import render_csv, render_html, render_sarif, render_terminal
from egyxos.scope import in_scope, normalize_target
from egyxos.methodology import planned_stages, stage_catalog


def test_scope_normalization_and_subdomain_matching():
    assert normalize_target("HTTPS://Example.COM/path") == "example.com"
    assert in_scope("a.example.com", "example.com")
    assert not in_scope("example.net", "example.com")


def test_private_scope_requires_explicit_flag():
    with pytest.raises(ScopeError):
        ScanContext("127.0.0.1")
    assert ScanContext("127.0.0.1", allow_private=True).target == "127.0.0.1"


def test_authorization_is_required():
    with pytest.raises(AuthorizationError):
        ScanContext("example.com").require_authorization()


def test_report_formats_are_valid():
    result = ScanResult("test", "example.com", assets=[Asset("https://example.com")])
    result.findings.append(Finding("test", parameter="id", injection_type="sqli",
                                   severity="high"))
    assert "example.com" in render_html(result)
    assert "asset" in render_csv(result)
    assert "injection_type" in render_csv(result)
    assert json.loads(render_sarif(result))["version"] == "2.1.0"


def test_terminal_report_has_compact_sections():
    result = ScanResult("test", "example.com", assets=[Asset("a.example.com", kind="host")])
    result.findings.append(__import__("egyxos.models", fromlist=["Finding"]).Finding(
        "Exposed service", severity="high"))
    output = render_terminal(result, color=False)
    assert "EGYXOS-SCANNER" in output
    assert "[✓] Scope validation" in output
    assert "HIGH" in output
    assert "Subdomains (1)" in output
    assert "a.example.com" in output


def test_pipeline_terminal_report_hides_raw_tool_stream():
    result = ScanResult("pipeline", "example.com", raw_output="tool banner and raw lines")
    result.errors.append({
        "error": "tool_execution_failed",
        "message": "External tool returned a non-zero exit code.",
        "details": {"tool": "nuclei", "returncode": 1, "stderr": "configuration error"},
    })
    output = render_terminal(result, color=False)
    assert "tool banner and raw lines" not in output
    assert "External tool returned a non-zero exit code. (nuclei)" in output
    assert "configuration error" in output


def test_terminal_report_does_not_duplicate_parsed_output():
    result = ScanResult("subfinder", "example.com",
                        assets=[Asset("a.example.com", kind="host")],
                        raw_output="a.example.com")
    output = render_terminal(result, color=False)
    assert output.count("a.example.com") == 1
    assert "Tool output" not in output


def test_line_scanner_filters_tool_banners():
    from egyxos.integrations.common import LineScanner

    class UrlScanner(LineScanner):
        name = "test"
        tool = "test"

        def command(self, context):
            return ["test"]

    scanner = UrlScanner()
    scanner.kind = "url"
    assert scanner._result_value("https://example.com/path") == "https://example.com/path"
    assert scanner._result_value("with <3 by @tool") is None
    assert scanner._result_value("  ___ tool banner ___") is None


def test_line_scanner_only_reports_open_services():
    from egyxos.integrations.common import LineScanner

    class ServiceScanner(LineScanner):
        name = "test"
        tool = "test"
        kind = "service"

        def command(self, context):
            return ["test"]

    scanner = ServiceScanner()
    assert scanner._result_value("443/tcp open https https") == "443/tcp open https https"
    assert scanner._result_value("1000 filtered tcp ports") is None
    assert scanner._result_value("Nmap done: 1 IP address") is None


def test_nuclei_command_uses_bounded_fast_defaults():
    from egyxos.integrations.nuclei import NucleiScanner

    context = ScanContext("example.com", authorized=True, threads=20, timeout=120)
    command = NucleiScanner().command(context)
    assert command[0:4] == ["nuclei", "-u", "example.com", "-silent"]
    assert command[command.index("-c") + 1] == "20"
    assert command[command.index("-bs") + 1] == "20"
    assert command[command.index("-timeout") + 1] == "10"
    assert command[command.index("-retries") + 1] == "0"


def test_arjun_uses_url_and_hides_diagnostic_stream():
    from egyxos.integrations.arjun import ArjunScanner

    context = ScanContext("example.com", authorized=True)
    scanner = ArjunScanner()
    assert scanner.command(context)[2] == "https://example.com"
    assert scanner.suppress_raw_output is True


def test_ffuf_preserves_http_url_scheme():
    from egyxos.integrations.ffuf import FfufScanner

    context = ScanContext("vulnweb.com", requested_target="https://vulnweb.com/",
                          authorized=True, config={"wordlist": "/tmp/words.txt"})
    command = FfufScanner().command(context)
    assert command[command.index("-u") + 1] == "https://vulnweb.com/FUZZ"


def test_cli_help_and_tools(capsys):
    assert main(["tools", "--json"]) == 0
    output = capsys.readouterr().out
    assert "subfinder" in output
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0


def test_short_scan_command_aliases():
    from egyxos.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["-d", "example.com", "--yes"]).command == "-d"
    assert parser.parse_args(["-s", "example.com", "--yes"]).command == "-s"
    assert parser.parse_args(["-v", "example.com", "--yes"]).command == "-v"
    assert parser.parse_args(["-h", "example.com", "--yes"]).command == "-h"
    assert parser.parse_args(["-c", "example.com", "--yes"]).command == "-c"
    assert parser.parse_args(["-u", "example.com", "--yes"]).command == "-u"
    assert parser.parse_args(["-p", "example.com", "--yes"]).command == "-p"
    assert parser.parse_args(["-f", "example.com", "--yes"]).command == "-f"
    assert parser.parse_args(["-n", "example.com", "--yes"]).command == "-n"
    options = parser.parse_args([
        "scan", "example.com", "-y", "-x", "30", "-T", "20", "-R", "50",
        "-S", "scope.txt", "-q", "-V", "-C", "-D", "-F", "json",
        "-O", "results", "-w", "words.txt", "-M", "deep", "-L", "high",
    ])
    assert options.yes_i_am_authorized is True
    assert options.timeout == 30
    assert options.threads == 20
    assert options.rate_limit == 50
    assert options.format == "json"
    assert options.profile == "deep"


def test_methodology_catalog_and_plan():
    catalog = stage_catalog()
    assert catalog[0]["key"] == "target"
    assert any(stage["name"] == "WAF detection" for stage in catalog)
    plan = planned_stages("standard", include_vuln=True)
    assert [stage["key"] for stage in plan][-2:] == ["finding_engine", "report"]
    assert "vulnerability" in [stage["key"] for stage in plan]
