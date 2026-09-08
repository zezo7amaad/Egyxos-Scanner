from .common import LineScanner


class KatanaScanner(LineScanner):
    name = "katana"
    tool = "katana"
    kind = "url"

    def command(self, context):
        return [self.tool, "-u", context.target, "-silent"]
