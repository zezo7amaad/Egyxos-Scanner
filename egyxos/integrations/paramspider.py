from .common import LineScanner


class ParamSpiderScanner(LineScanner):
    name = "paramspider"
    tool = "paramspider"
    kind = "url"

    def command(self, context):
        return [self.tool, "-d", context.target]
