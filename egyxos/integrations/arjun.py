from .common import LineScanner


class ArjunScanner(LineScanner):
    name = "arjun"
    tool = "arjun"
    kind = "url"

    def command(self, context):
        return [self.tool, "-u", context.target, "--stable"]
