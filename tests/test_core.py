import json

import pytest

from egyxos.cli import main
from egyxos.context import ScanContext
from egyxos.errors import AuthorizationError, ScopeError
from egyxos.models import Asset, ScanResult
from egyxos.reporting import render_csv, render_html, render_sarif, render_terminal
from egyxos.scope import in_scope, normalize_target


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
    result.findings.append(__import__("egyxos.models", fromlist=["Finding"]).Finding("test", severity="high"))
    assert "example.com" in render_html(result)
    assert "asset" in render_csv(result)
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


def test_cli_help_and_tools(capsys):
    assert main(["tools", "--json"]) == 0
    output = capsys.readouterr().out
    assert "subfinder" in output
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0
