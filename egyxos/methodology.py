"""Declarative reconnaissance methodology and stage metadata."""

from dataclasses import asdict, dataclass
from typing import Dict, List


@dataclass(frozen=True)
class MethodologyStage:
    key: str
    name: str
    purpose: str
    tools: List[str]
    optional: bool = False
    opt_in: str = ""


STAGES = (
    MethodologyStage("target", "Target", "Normalize the authorized target.", []),
    MethodologyStage("scope_validation", "Scope validation",
                     "Enforce authorization, scope, and private-target controls.", []),
    MethodologyStage("subdomains", "Subdomain discovery",
                     "Expand the authorized asset inventory.", ["subfinder"]),
    MethodologyStage("http", "HTTP enrichment",
                     "Identify reachable web services and technologies.",
                     ["httpx"]),
    MethodologyStage("endpoints", "Endpoint discovery",
                     "Collect crawled and historical endpoints.", ["katana", "paramspider"]),
    MethodologyStage("parameters", "Parameter discovery",
                     "Find candidate HTTP parameters.", ["arjun"]),
    MethodologyStage("fuzzing", "Directory and file fuzzing",
                     "Discover explicitly authorized content paths.", ["ffuf"], opt_in="--wordlist"),
    MethodologyStage("ports", "IP and open ports",
                     "Identify exposed services on authorized targets.", ["nmap"]),
    MethodologyStage("screenshots", "Screenshot gathering",
                     "Capture visual evidence for reachable web assets.",
                     ["gowitness"], optional=True),
    MethodologyStage("vulnerability", "Vulnerability scan",
                     "Run non-destructive template and specialist checks.",
                     ["nuclei", "dalfox", "crlfuzz", "s3scanner"], optional=True,
                     opt_in="--include-vuln"),
    MethodologyStage("whois", "WHOIS identification",
                     "Collect public registration metadata.", ["whois"], optional=True),
    MethodologyStage("waf", "WAF detection",
                     "Identify common web application firewall signals.",
                     ["wafw00f"], optional=True),
    MethodologyStage("sqli", "SQL injection checks",
                     "Run SQLmap only after explicit operator opt-in.",
                     ["sqlmap"], optional=True, opt_in="--i-understand-sqlmap"),
    MethodologyStage("finding_engine", "Finding engine",
                     "Normalize evidence, severity, confidence, and remediation.", []),
    MethodologyStage("report", "Report",
                     "Render terminal or requested machine-readable output.", []),
)


def stage_catalog() -> List[Dict[str, object]]:
    return [asdict(stage) for stage in STAGES]


def planned_stages(profile: str, *, include_vuln: bool = False,
                   include_sqli: bool = False) -> List[Dict[str, object]]:
    selected = {"target", "scope_validation", "subdomains", "http", "endpoints",
                "parameters", "ports", "finding_engine", "report"}
    if profile == "passive":
        selected -= {"endpoints", "parameters", "ports"}
    if profile == "deep":
        selected.add("fuzzing")
    if include_vuln:
        selected.add("vulnerability")
    if include_sqli:
        selected.add("sqli")
    return [stage for stage in stage_catalog() if stage["key"] in selected]
