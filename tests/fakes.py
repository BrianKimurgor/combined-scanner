import json
import sys

from scanner.normalize.finding import Category, Finding, Severity
from scanner.plugins.base import CommandResult, Parsed, ScanContext, ScannerPlugin


class ScriptPlugin(ScannerPlugin):
    """Runs the current Python interpreter so resilience paths use a real subprocess."""

    binary = sys.executable
    code = "import json; print(json.dumps({'severity': 'high'}))"

    def build_command(self, ctx: ScanContext) -> list[str]:
        return [self.binary, "-c", self.code]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        data = json.loads(proc.stdout)
        finding = Finding(
            tool=self.name,
            category=Category.CODE,
            rule_id="R1",
            severity=Severity(data["severity"]),
            title="t",
            file="a.py",
            line_start=1,
        )
        return Parsed([finding])


class GoodPlugin(ScriptPlugin):
    name = "good"


class LowPlugin(ScriptPlugin):
    name = "low"
    code = "import json; print(json.dumps({'severity': 'low'}))"


class FailingPlugin(ScriptPlugin):
    name = "failing"
    code = "import sys; sys.stderr.write('boom'); sys.exit(3)"


class SlowPlugin(ScriptPlugin):
    name = "slow"
    code = "import time; time.sleep(30)"


class GarbagePlugin(ScriptPlugin):
    name = "garbage"
    code = "print('not json')"


class MissingPlugin(ScriptPlugin):
    name = "missing"
    binary = "definitely-not-an-installed-scanner"


class CrashingPlugin(ScriptPlugin):
    name = "crashing"

    def build_command(self, ctx: ScanContext) -> list[str]:
        raise RuntimeError("bug in plugin")


_GREP = """
import json, os
hits = []
for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d != ".git"]
    for name in sorted(files):
        path = os.path.join(root, name)
        try:
            lines = open(path, encoding="utf-8").read().splitlines()
        except Exception:
            continue
        for number, text in enumerate(lines, 1):
            if "VULN" in text:
                hits.append({"file": os.path.relpath(path).replace(os.sep, "/"), "line": number})
print(json.dumps(hits))
"""


class VulnGrepPlugin(ScannerPlugin):
    """Reports a high 'code' finding on every line containing VULN, from the scanned directory."""

    name = "grep"
    binary = sys.executable

    def build_command(self, ctx: ScanContext) -> list[str]:
        return [self.binary, "-c", _GREP]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        return Parsed(
            [
                Finding(
                    tool=self.name,
                    category=Category.CODE,
                    rule_id="R-vuln",
                    severity=Severity.HIGH,
                    title="vulnerable line",
                    message="this line is vulnerable",
                    file=hit["file"],
                    line_start=hit["line"],
                )
                for hit in json.loads(proc.stdout)
            ]
        )


class FlakyPlugin(VulnGrepPlugin):
    """Behaves like VulnGrepPlugin, but fails in any tree that contains a file named FAIL_ME."""

    name = "flaky"

    def build_command(self, ctx: ScanContext) -> list[str]:
        code = "import os, sys\nif os.path.exists('FAIL_ME'): sys.exit(3)\n" + _GREP
        return [self.binary, "-c", code]


class DuplicationPlugin(ScriptPlugin):
    """Reports no findings but a duplication_percent read from a file named PERCENT."""

    name = "dup"
    code = "import json; print(json.dumps(float(open('PERCENT').read())))"

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        return Parsed([], {"duplication_percent": float(json.loads(proc.stdout))})
