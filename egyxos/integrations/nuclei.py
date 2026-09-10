from .common import LineScanner


class NucleiScanner(LineScanner):
    name = "nuclei"
    tool = "nuclei"
    kind = "finding"

    def command(self, context):
        request_timeout = min(max(int(context.timeout), 1), 10)
        command = [
            self.tool,
            "-u", context.target,
            "-silent",
            "-jsonl",
            "-c", str(max(1, context.threads)),
            "-bs", str(max(1, context.threads)),
            "-timeout", str(request_timeout),
            "-retries", "0",
        ]
        if context.rate_limit is not None:
            command.extend(["-rl", str(max(1, int(context.rate_limit)) )])
        return command
