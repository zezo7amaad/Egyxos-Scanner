"""Per-run state and cancellation handling."""

from dataclasses import dataclass, field
from pathlib import Path
import sys
from threading import Event
from typing import Any, Dict, Optional

from .errors import AuthorizationError
from .scope import in_scope, normalize_target, validate_scope


@dataclass
class ScanContext:
    target: str
    requested_target: Optional[str] = None
    authorized: bool = False
    allow_private: bool = False
    timeout: float = 120.0
    output_dir: Path = Path("egyxos-results")
    config: Dict[str, Any] = field(default_factory=dict)
    scope_file: Optional[Path] = None
    profile: str = "standard"
    severity: str = "info"
    threads: int = 10
    rate_limit: Optional[float] = None
    cancel_event: Event = field(default_factory=Event, repr=False)

    def __post_init__(self):
        if self.requested_target is None:
            self.requested_target = self.target
        self.target = validate_scope(self.target, allow_private=self.allow_private)
        self.output_dir = Path(self.output_dir)
        if self.scope_file:
            self.scope_file = Path(self.scope_file).expanduser()
            if not self.scope_file.is_file():
                raise ValueError(f"Scope file does not exist: {self.scope_file}")
            allowed = {
                normalize_target(line.strip())
                for line in self.scope_file.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            }
            if not allowed or not any(in_scope(self.target, item) or in_scope(item, self.target)
                                      for item in allowed):
                raise ValueError("Target is not present in the authorized scope file.")

    def require_authorization(self):
        if not self.authorized:
            print(
                "WARNING: Only scan systems you own or have explicit permission to test.\n"
                f"Target: {self.requested_target or self.target}",
                file=sys.stderr,
            )
            raise AuthorizationError(
                "Authorized security testing confirmation is required. "
                "Pass --yes-i-am-authorized (or set EGYXOS_AUTHORIZED=1)."
            )

    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def cancel(self):
        self.cancel_event.set()
