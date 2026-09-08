from .common import LineScanner


class NucleiScanner(LineScanner):
    name = "nuclei"
    tool = "nuclei"
    kind = "finding"

    def command(self, context):
        return [self.tool, "-u", context.target, "-silent", "-jsonl"]
