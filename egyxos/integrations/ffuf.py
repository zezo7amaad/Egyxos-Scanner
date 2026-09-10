from .common import LineScanner


class FfufScanner(LineScanner):
    name = "ffuf"
    tool = "ffuf"
    kind = "url"

    def command(self, context):
        # A URL is intentionally not inferred as a wordlist or a destructive action.
        wordlist = context.config.get("wordlist")
        if not wordlist:
            raise ValueError("fuzz requires a configured wordlist (--wordlist or config.wordlist).")
        target = context.requested_target or context.target
        if not target.lower().startswith(("http://", "https://")):
            target = "https://" + target
        return [self.tool, "-u", target.rstrip("/") + "/FUZZ",
                "-w", str(wordlist), "-noninteractive"]
