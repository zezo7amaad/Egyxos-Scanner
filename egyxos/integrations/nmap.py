from .common import LineScanner


class NmapScanner(LineScanner):
    name = "nmap"
    tool = "nmap"
    kind = "service"

    def command(self, context):
        return [self.tool, "-sV", "--", context.target]
