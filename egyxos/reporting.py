"""Terminal and file report serializers."""

import csv
import html
import io
import json
from pathlib import Path
from typing import Any, Dict

from .models import ScanResult


def as_payload(result: ScanResult) -> Dict[str, Any]:
    return result.to_dict()


def render_json(result: ScanResult, *, pretty: bool = True) -> str:
    return json.dumps(as_payload(result), indent=2 if pretty else None, sort_keys=True)


def render_csv(result: ScanResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "severity", "title", "target", "source", "description"])
    for asset in result.assets:
        writer.writerow(["asset", asset.value, "", "", "", asset.source or "", ""])
    for finding in result.findings:
        writer.writerow(["finding", finding.evidence or "", finding.severity, finding.title,
                         finding.target or "", finding.source or "", finding.description])
    return output.getvalue()


def render_html(result: ScanResult) -> str:
    rows = []
    for asset in result.assets:
        rows.append("<tr><td>asset</td><td>{}</td><td></td><td>{}</td></tr>".format(
            html.escape(asset.value), html.escape(asset.source or "")))
    for finding in result.findings:
        rows.append("<tr><td>finding</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(finding.evidence or ""), html.escape(finding.severity),
            html.escape(finding.title)))
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Egyxos report</title><style>body{{font:16px system-ui;max-width:1100px;margin:auto}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.5rem}}</style>
<h1>Egyxos report</h1><p>Scanner: <b>{}</b> &middot; Target: <b>{}</b></p>
<table><thead><tr><th>Type</th><th>Value/evidence</th><th>Severity</th><th>Source/title</th></tr></thead>
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


def render_terminal(result: ScanResult) -> str:
    lines = [
        f"Egyxos | {result.scanner}",
        f"Target: {result.target}",
        f"Assets: {len(result.assets)} | Findings: {len(result.findings)}",
    ]
    if result.raw_output.strip():
        lines.extend(["", "Tool output", "-----------", result.raw_output.rstrip()])
    if result.findings:
        lines.extend(["", "Findings", "--------"])
        lines.extend(f"[{finding.severity}] {finding.title}" for finding in result.findings)
    if result.assets and not result.raw_output.strip():
        lines.extend(["", "Assets", "------"])
        lines.extend(f"{asset.kind}: {asset.value}" for asset in result.assets)
    lines.extend(f"  error: {error.get('message', error)}" for error in result.errors)
    return "\n".join(lines)


def render(result: ScanResult, fmt: str) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "csv":
        return render_csv(result)
    if fmt == "html":
        return render_html(result)
    if fmt == "sarif":
        return render_sarif(result)
    return render_terminal(result)


def write_report(result: ScanResult, path: Path, fmt: str = None) -> Path:
    path = Path(path)
    fmt = fmt or path.suffix.lstrip(".") or "json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(result, fmt), encoding="utf-8")
    return path
