"""Terminal and file report serializers."""

import csv
import html
import io
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from .models import ScanResult


RESET = "\033[0m"
COLORS = {
    "cyan": "\033[36m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "magenta": "\033[35m",
    "dim": "\033[2m",
    "bold": "\033[1m",
}
SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _color(text: str, name: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{COLORS[name]}{text}{RESET}"


def _terminal_colors_enabled() -> bool:
    return bool(sys.stdout.isatty() and os.environ.get("NO_COLOR") is None)


def as_payload(result: ScanResult) -> Dict[str, Any]:
    return result.to_dict()


def render_json(result: ScanResult, *, pretty: bool = True) -> str:
    return json.dumps(as_payload(result), indent=2 if pretty else None, sort_keys=True)


def render_csv(result: ScanResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["target", "parameter", "injection_type", "evidence",
                     "confidence", "severity", "remediation"])
    for asset in result.assets:
        writer.writerow([asset.value, "", "asset", asset.source or "",
                         "", "info", ""])
    for finding in result.findings:
        writer.writerow([
            finding.target or result.target,
            finding.parameter or finding.endpoint or "",
            finding.injection_type or finding.title,
            finding.evidence or finding.description,
            finding.confidence,
            finding.severity,
            finding.remediation or "",
        ])
    return output.getvalue()


def render_html(result: ScanResult) -> str:
    rows = []
    for finding in result.findings:
        rows.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                    "<td>{}</td><td>{}</td></tr>".format(
            html.escape(finding.target or result.target),
            html.escape(finding.parameter or finding.endpoint or ""),
            html.escape(finding.injection_type or finding.title),
            html.escape(finding.evidence or finding.description),
            html.escape(finding.confidence),
            html.escape(finding.severity),
            html.escape(finding.remediation or "")))
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Egyxos report</title><style>body{{font:16px system-ui;max-width:1100px;margin:auto}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.5rem}}</style>
<h1>Egyxos report</h1><p>Scanner: <b>{}</b> &middot; Target: <b>{}</b></p>
<table><thead><tr><th>Target</th><th>Parameter</th><th>Injection type</th><th>Evidence</th>
<th>Confidence</th><th>Severity</th><th>Remediation</th></tr></thead>
<tbody>{}</tbody></table></html>""".format(html.escape(result.scanner), html.escape(result.target), "".join(rows))


def render_sarif(result: ScanResult) -> str:
    rules = []
    results = []
    for index, finding in enumerate(result.findings, 1):
        rule_id = "egyxos/" + (finding.source or result.scanner) + "/" + str(index)
        rules.append({"id": rule_id, "name": finding.title, "shortDescription": {"text": finding.title}})
        results.append({
            "ruleId": rule_id,
            "level": {"critical": "error", "high": "error", "medium": "warning"}.get(finding.severity, "note"),
            "message": {"text": finding.description or finding.title},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.target or result.target}}}],
        })
    payload = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
               "runs": [{"tool": {"driver": {"name": "egyxos", "rules": rules}}, "results": results}]}
    return json.dumps(payload, indent=2)


def render_terminal(result: ScanResult, *, color: bool = None) -> str:
    if color is None:
        color = _terminal_colors_enabled()
    title = "EGYXOS-SCANNER"
    width = 42
    border = "═" * width
    lines = [
        _color(f"╔{border}╗", "cyan", color),
        _color(f"║{title.center(width)}║", "bold", color),
        _color(f"╚{border}╝", "cyan", color),
        "",
        f"Target: {result.target}",
        "Mode:   authorized assessment",
        "",
        _color("[✓] Scope validation", "green", color),
        "",
        _color("Methodology", "bold", color),
        _color(_methodology_text(result), "dim", color),
        "",
        _color("Results", "bold", color),
    ]
    counts = {}
    for asset in result.assets:
        counts[asset.kind] = counts.get(asset.kind, 0) + 1
    labels = (
        ("host", "Subdomains"),
        ("url", "URLs"),
        ("parameter", "Parameters"),
        ("service", "Services"),
    )
    for kind, label in labels:
        if kind in counts:
            lines.append(f"[✓] {label:<16} {counts[kind]}")
    finding_marker = "[!]" if result.findings else "[✓]"
    lines.append(f"{_color(finding_marker, 'yellow' if result.findings else 'green', color)} "
                 f"{'Findings':<16} {len(result.findings)}")
    if result.findings:
        severity_counts = {}
        for finding in result.findings:
            severity = finding.severity.lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        lines.extend(["", _color("Findings", "bold", color), _color("─" * width, "dim", color)])
        for severity in ("critical", "high", "medium", "low", "info"):
            if severity in severity_counts:
                label = severity.upper().ljust(10)
                lines.append(_color(f"{label} {severity_counts[severity]}",
                                    SEVERITY_COLORS[severity], color))
        lines.extend(["", _color("Finding details", "bold", color),
                      _color("─" * width, "dim", color)])
        for finding in result.findings:
            location = finding.parameter or finding.endpoint or finding.target or result.target
            kind = finding.injection_type or finding.title
            lines.append(
                f"{_color(finding.severity.upper(), SEVERITY_COLORS.get(finding.severity.lower(), 'dim'), color)} "
                f"{kind} @ {location} [{finding.confidence}]")
            if finding.evidence:
                lines.append(f"  evidence: {finding.evidence}")
            if finding.remediation:
                lines.append(f"  remediation: {finding.remediation}")
    if result.assets:
        grouped_assets = {}
        for asset in result.assets:
            grouped_assets.setdefault(asset.kind, []).append(asset.value)
        asset_labels = {
            "host": "Subdomains",
            "url": "URLs",
            "parameter": "Parameters",
            "service": "Services",
        }
        lines.extend(["", _color("Discovered assets", "bold", color),
                      _color("─" * width, "dim", color)])
        for kind, values in grouped_assets.items():
            label = asset_labels.get(kind, kind.title())
            lines.append(_color(f"{label} ({len(values)})", "cyan", color))
            lines.extend(f"  {value}" for value in dict.fromkeys(values))
    if result.errors:
        lines.extend(["", _color("Errors", "bold", color)])
        for error in result.errors:
            details = error.get("details", {}) if isinstance(error, dict) else {}
            tool = details.get("tool")
            suffix = f" ({tool})" if tool else ""
            lines.append(f"{_color('[!]', 'red', color)} "
                         f"{error.get('message', error)}{suffix}")
            stderr = details.get("stderr")
            if stderr:
                lines.append(f"    {stderr.strip().splitlines()[-1]}")
            if details.get("timeout") is not None:
                lines.append(f"    Timeout: {details['timeout']} seconds; use --timeout to increase it.")
            argv = details.get("argv")
            if argv and details.get("tool") == "httpx" and stderr and "no such option" in stderr.lower():
                lines.append("    Expected ProjectDiscovery httpx; run: egyxos tools versions")
    if result.raw_output.strip() and result.scanner != "pipeline":
        lines.extend(["", _color("Tool output", "bold", color),
                      _color("─" * width, "dim", color), result.raw_output.rstrip()])
    return "\n".join(lines)


def _methodology_text(result: ScanResult) -> str:
    stages = result.metadata.get("stages", [])
    if not stages:
        return "Authorized scanner result"
    return " -> ".join(stage["name"] for stage in stages)


def render(result: ScanResult, fmt: str, *, color: bool = None) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "csv":
        return render_csv(result)
    if fmt == "html":
        return render_html(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_terminal(result, color=color)


def write_report(result: ScanResult, path: Path, fmt: str = None) -> Path:
    path = Path(path)
    fmt = fmt or path.suffix.lstrip(".") or "json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(result, fmt), encoding="utf-8")
    return path
