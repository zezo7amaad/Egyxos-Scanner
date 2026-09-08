"""Scanner abstractions and safe external process execution."""

import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional

from .context import ScanContext
from .errors import ToolExecutionError, ToolNotFoundError
from .models import ScanResult


@dataclass
class CommandResult:
    argv: List[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float


class BaseScanner(ABC):
    name = "base"
    tool = ""

    @abstractmethod
    def scan(self, context: ScanContext) -> ScanResult:
        raise NotImplementedError

    def check_dependencies(self) -> bool:
        return bool(self.tool and shutil.which(self.tool))

    def validate(self, context: ScanContext) -> None:
        context.require_authorization()

    def parse(self, output: str):
        return output.splitlines()

    def normalize(self, parsed):
        return parsed


class ExternalTool:
    """Execute an argv list without a shell, with timeout and cancellation."""

    def __init__(self, executable: str, *, timeout: Optional[float] = None):
        self.executable = executable
        self.timeout = timeout

    def available(self) -> bool:
        return shutil.which(self.executable) is not None

    def run(self, argv: List[str], context: ScanContext) -> CommandResult:
        if not argv or any(not isinstance(item, str) for item in argv):
            raise ToolExecutionError("External commands must be non-empty argv lists.")
        if not self.available():
            raise ToolNotFoundError(
                "Required external tool is not installed.",
                details={"tool": self.executable, "install_hint": f"Install {self.executable} and retry."},
            )
        started = time.monotonic()
        try:
            process = subprocess.Popen(
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", shell=False,
            )
        except OSError as exc:
            raise ToolExecutionError("Could not start external tool.", details={"tool": self.executable, "reason": str(exc)})
        limit = self.timeout if self.timeout is not None else context.timeout
        while process.poll() is None:
            if context.cancelled():
                process.kill()
                process.communicate()
                raise ToolExecutionError("Scan cancelled.", details={"tool": self.executable})
            if time.monotonic() - started > limit:
                process.kill()
                stdout, stderr = process.communicate()
                raise ToolExecutionError(
                    "External tool timed out.",
                    details={"tool": self.executable, "timeout": limit, "stderr": stderr[-1000:]},
                )
            time.sleep(0.05)
        stdout, stderr = process.communicate()
        result = CommandResult(argv, process.returncode, stdout, stderr, time.monotonic() - started)
        if process.returncode != 0:
            raise ToolExecutionError(
                "External tool returned a non-zero exit code.",
                details={"tool": self.executable, "returncode": process.returncode, "stderr": stderr[-2000:]},
            )
        return result
