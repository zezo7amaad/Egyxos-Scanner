import json

import pytest

from egyxos.cli import main
from egyxos.context import ScanContext
from egyxos.errors import AuthorizationError, ScopeError
from egyxos.models import Asset, ScanResult
from egyxos.reporting import render_csv, render_html, render_sarif
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


def test_cli_help_and_tools(capsys):
    assert main(["tools", "--json"]) == 0
    output = capsys.readouterr().out
    assert "subfinder" in output
    with pytest.raises(SystemExit) as raised:
        main(["--help"])
    assert raised.value.code == 0
