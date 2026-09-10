"""Normalized data models shared by scanners and report writers."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Asset:
    value: str
    kind: str = "host"
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    title: str
    id: str = ""
    severity: str = "info"
    confidence: str = "medium"
    target: Optional[str] = None
    endpoint: Optional[str] = None
    description: str = ""
    evidence: Optional[str] = None
    references: List[str] = field(default_factory=list)
    scanner: Optional[str] = None
    timestamp: str = field(default_factory=utc_now)
    remediation: Optional[str] = None
    source: Optional[str] = None  # compatibility alias for older result files
    metadata: Dict[str, Any] = field(default_factory=dict)
    parameter: Optional[str] = None
    injection_type: Optional[str] = None


@dataclass
class ScanResult:
    scanner: str
    target: str
    started_at: str = field(default_factory=utc_now)
    finished_at: Optional[str] = None
    assets: List[Asset] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    raw_output: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)

    def finish(self):
        self.finished_at = utc_now()
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def merge(self, other: "ScanResult") -> "ScanResult":
        self.assets.extend(other.assets)
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        if other.raw_output:
            self.raw_output += ("\n" if self.raw_output else "") + other.raw_output
        self.metadata.update(other.metadata)
        return self


# Descriptive aliases make the normalized contract discoverable without
# requiring callers to depend on a particular internal naming convention.
NormalizedAsset = Asset
NormalizedFinding = Finding
ScanSummary = ScanResult
