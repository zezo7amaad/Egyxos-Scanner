from .common import LineScanner


class HttpxScanner(LineScanner):
    name = "httpx"
    tool = "httpx"
    kind = "url"

    def command(self, context):
        return [self.tool, "-u", context.target, "-silent"]
