from .common import LineScanner
from ..errors import AuthorizationError
from ..models import Finding


class SqlmapScanner(LineScanner):
    name = "sqlmap"
    tool = "sqlmap"
    kind = "finding"
    suppress_raw_output = True
    retain_tool_output = True

    def scan(self, context):
        result = super().scan(context)
        output = result.metadata.pop("_tool_output", "")
        lowered = output.lower()
        target = context.requested_target or context.target
        if "is vulnerable" in lowered or "is injectable" in lowered:
            result.findings.append(Finding(
                title="SQL injection detected",
                injection_type="sql injection",
                target=target,
                evidence=self._evidence(output),
                confidence="high",
                severity="high",
                remediation="Use parameterized queries and server-side input validation.",
                source=self.name,
            ))
        else:
            result.metadata["status"] = "No injectable parameters detected."
        return result

    def _result_value(self, line: str):
        return None

    @staticmethod
    def _evidence(output):
        lines = [
            line.strip() for line in output.splitlines()
            if "injectable" in line.lower() or "is vulnerable" in line.lower()
        ]
        return " ".join(lines[-3:])

    def command(self, context):
        if not context.config.get("sqlmap_opt_in", False):
            raise AuthorizationError(
                "SQLmap is disabled by default. Set sqlmap_opt_in=true and pass --i-understand-sqlmap."
            )
        # Never add --batch or destructive flags implicitly; the caller opts in explicitly.
        target = context.requested_target or context.target
        if not target.lower().startswith(("http://", "https://")):
            raise ValueError("sqli requires an explicit http(s) URL.")
        command = [self.tool, "-u", target, "--batch", "--level=1", "--risk=1"]
        return command
