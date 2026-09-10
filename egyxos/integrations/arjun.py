from .common import LineScanner


class ArjunScanner(LineScanner):
    name = "arjun"
    tool = "arjun"
    kind = "url"
    suppress_raw_output = True

    def command(self, context):
        target = context.target
        if not target.lower().startswith(("http://", "https://")):
            target = "https://" + target
        return [self.tool, "-u", target, "--stable"]
