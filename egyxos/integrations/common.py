from typing import List

from ..context import ScanContext
from ..models import Asset, ScanResult
from ..scanners import BaseScanner, ExternalTool


class LineScanner(BaseScanner):
    """Common adapter for tools that emit one useful item per line."""

    kind = "url"

    def command(self, context: ScanContext) -> List[str]:
        raise NotImplementedError

    def scan(self, context: ScanContext) -> ScanResult:
        context.require_authorization()
        result = ScanResult(self.name, context.target)
        command = self.command(context)
        output = ExternalTool(self.tool).run(command, context)
        result.raw_output = output.stdout
        seen = set()
        for line in output.stdout.splitlines():
            value = line.strip()
            if value and not value.startswith("#") and value not in seen:
                seen.add(value)
                result.assets.append(Asset(value=value, kind=self.kind, source=self.name))
        result.metadata["command"] = command
        return result.finish()
