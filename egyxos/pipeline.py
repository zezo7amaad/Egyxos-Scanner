"""Orchestration for one scanner or the conservative recon pipeline."""

from .errors import EgyxosError
from .integrations import SCANNERS
from .models import ScanResult


def run_scanner(name, context) -> ScanResult:
    scanner_type = SCANNERS.get(name)
    if scanner_type is None:
        raise EgyxosError("Unknown scanner.", details={"scanner": name})
    return scanner_type().scan(context)


def run_pipeline(context, *, include_vuln: bool = False, only=None, exclude=None,
                 no_subdomains: bool = False, no_ports: bool = False,
                 no_vuln: bool = False) -> ScanResult:
    context.require_authorization()
    combined = ScanResult("pipeline", context.target)
    names = ["subfinder", "http", "crawl", "urls", "params", "ports"]
    if context.profile == "passive":
        names = ["subfinder", "http", "urls"]
    elif context.profile == "deep":
        names += ["fuzz"]
    if include_vuln and not no_vuln:
        names.append("vuln")
    if no_subdomains:
        names = [name for name in names if name != "subfinder"]
    if no_ports:
        names = [name for name in names if name != "ports"]
    if only:
        selected = {item.strip() for item in only.split(",") if item.strip()}
        names = [name for name in names if name in selected or
                 (name == "http" and "httpx" in selected)]
    if exclude:
        skipped = {item.strip() for item in exclude.split(",") if item.strip()}
        names = [name for name in names if name not in skipped]
    if context.config.get("sqlmap_opt_in") and "sqli" not in names:
        names.append("sqli")
    for name in names:
        try:
            combined.merge(run_scanner(name, context))
        except EgyxosError as exc:
            combined.errors.append(exc.as_dict())
    return combined.finish()
