from .common import LineScanner
from ..errors import AuthorizationError


class SqlmapScanner(LineScanner):
    name = "sqlmap"
    tool = "sqlmap"
    kind = "finding"

    def command(self, context):
        if not context.config.get("sqlmap_opt_in", False):
            raise AuthorizationError(
                "SQLmap is disabled by default. Set sqlmap_opt_in=true and pass --i-understand-sqlmap."
            )
        # Never add --batch or destructive flags implicitly; the caller opts in explicitly.
        target = context.requested_target or context.target
        if not target.lower().startswith(("http://", "https://")):
            raise ValueError("sqli requires an explicit http(s) URL.")
        return [self.tool, "-u", target, "--batch", "--level=1", "--risk=1"]
