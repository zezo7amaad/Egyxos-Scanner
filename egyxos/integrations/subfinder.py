from .common import LineScanner


class SubfinderScanner(LineScanner):
    name = "subfinder"
    tool = "subfinder"
    kind = "host"

    def command(self, context):
        return [self.tool, "-d", context.target, "-silent"]
