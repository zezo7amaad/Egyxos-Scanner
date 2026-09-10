import re
from typing import List

from ..context import ScanContext
from ..models import Asset, ScanResult
from ..scanners import BaseScanner, ExternalTool


class LineScanner(BaseScanner):
    """Common adapter for tools that emit one useful item per line."""

    kind = "url"
    suppress_raw_output = False
    retain_tool_output = False

    def command(self, context: ScanContext) -> List[str]:
        raise NotImplementedError

    def scan(self, context: ScanContext) -> ScanResult:
        context.require_authorization()
        result = ScanResult(self.name, context.target)
        command = self.command(context)
        output = ExternalTool(self.tool).run(command, context)
        if self.retain_tool_output:
            result.metadata["_tool_output"] = output.stdout
        if not self.suppress_raw_output:
            result.raw_output = output.stdout
        seen = set()
        for line in output.stdout.splitlines():
            value = self._result_value(line)
            if value and value not in seen:
                seen.add(value)
                result.assets.append(Asset(value=value, kind=self.kind, source=self.name))
        result.metadata["command"] = command
        return result.finish()

    def _result_value(self, line: str):
        value = line.strip()
        if not value or value.startswith("#") or self._looks_like_banner(value):
            return None
        if self.kind == "service":
            if " open " not in f" {value.lower()} " or "/tcp" not in value.lower():
                return None
            return value
        if self.kind == "url" and not value.lower().startswith(("http://", "https://")):
            return None
        if self.kind == "host" and not re.match(
                r"^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$", value):
            return None
        return value

    @staticmethod
    def _looks_like_banner(value: str) -> bool:
        lowered = value.lower()
        return (
            "with <3 by" in lowered
            or "powered by" in lowered
            or "github.com/" in lowered
            or len(value) > 300
            or any(marker in value for marker in ("\\_", "*/", "___", "╔", "╚"))
        )
