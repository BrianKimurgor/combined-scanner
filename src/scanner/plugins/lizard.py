import csv
import io
import os
import shutil
import subprocess
import time

from scanner.core.ignore import is_ignored
from scanner.normalize import severity
from scanner.normalize.finding import Category, Finding
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    PluginResult,
    ScanContext,
    ScannerPlugin,
    Status,
    rel_path,
)

# CSV columns: NLOC, CCN, token, PARAM, length, location, file, function, long_name, start, end
_MIN_COLUMNS = 11
# Minified or generated files give lizard enormous "function" names; the csv default is 128 KiB.
csv.field_size_limit(2**30)
BATCH_FILES = 500  # keeps the command line short and bounds the work of one retry


class LizardPlugin(ScannerPlugin):
    name = "lizard"
    binary = "lizard"

    def build_command(self, ctx: ScanContext) -> list[str]:
        # Lizard matches ./-prefixed paths with fnmatch, where * already crosses directories.
        patterns = [*ctx.config.ignore, *ctx.config.quality_ignore]
        excludes = [arg for p in patterns for arg in ("-x", p.replace("**", "*"))]
        return ["lizard", "--csv", *excludes, "."]

    def run(self, ctx: ScanContext) -> PluginResult:
        result = super().run(ctx)
        # Lizard's parser can raise on odd source files and then reports nothing at all.
        if result.status is Status.FAILED and result.message.startswith("exit code"):
            return self._run_per_file(ctx, result)
        return result

    def _run_per_file(self, ctx: ScanContext, failed: PluginResult) -> PluginResult:
        exe = shutil.which(self.binary)
        if exe is None:
            return failed
        started = time.monotonic()
        deadline = started + ctx.timeout
        files = self._source_files(ctx)
        outputs: list[str] = []
        skipped: list[str] = []
        for start in range(0, len(files), BATCH_FILES):
            self._collect(exe, ctx, files[start : start + BATCH_FILES], outputs, skipped, deadline)
        if time.monotonic() > deadline or (not outputs and skipped):
            return failed
        parsed = self.parse(ctx, CommandResult(0, "\n".join(outputs), ""))
        note = f"{len(skipped)} file(s) skipped because lizard could not parse them"
        return PluginResult(
            tool=self.name,
            status=Status.OK,
            findings=parsed.findings,
            message=note if skipped else "",
            duration_seconds=round(time.monotonic() - started + failed.duration_seconds, 3),
        )

    @staticmethod
    def _source_files(ctx: ScanContext) -> list[str]:
        found: list[str] = []
        for dirpath, dirnames, filenames in os.walk(ctx.workdir):
            base = os.path.relpath(dirpath, ctx.workdir).replace(os.sep, "/")
            prefix = "" if base == "." else base + "/"
            dirnames[:] = sorted(
                d
                for d in dirnames
                if d != ".git" and not is_ignored(f"{prefix}{d}/", ctx.config.ignore)
            )
            skip = [*ctx.config.ignore, *ctx.config.quality_ignore]
            found += [
                f"{prefix}{name}"
                for name in sorted(filenames)
                if not is_ignored(f"{prefix}{name}", skip)
            ]
        return found

    def _collect(
        self,
        exe: str,
        ctx: ScanContext,
        files: list[str],
        outputs: list[str],
        skipped: list[str],
        deadline: float,
    ) -> None:
        """Run lizard on files; when it fails, split the list to find the files that crash it."""
        if not files or time.monotonic() > deadline:
            return
        remaining = max(1, int(deadline - time.monotonic()))
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [exe, "--csv", *files],
                cwd=ctx.workdir,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=remaining,
                check=False,
                env={**os.environ, **self.env},
            )
        except (subprocess.TimeoutExpired, OSError):
            return
        if done.returncode == 0:
            outputs.append(done.stdout)
        elif len(files) == 1:
            skipped.append(files[0])
        else:
            middle = len(files) // 2
            self._collect(exe, ctx, files[:middle], outputs, skipped, deadline)
            self._collect(exe, ctx, files[middle:], outputs, skipped, deadline)

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        limits = ctx.config.gate.complexity
        findings: list[Finding] = []
        for row in csv.reader(io.StringIO(proc.stdout)):
            if len(row) < _MIN_COLUMNS:
                continue
            try:
                ccn, params, length = int(row[1]), int(row[3]), int(row[4])
                start, end = int(row[9]), int(row[10])
            except ValueError:
                continue
            exceeded = []
            if ccn > limits.ccn:
                exceeded.append(f"complexity {ccn} > {limits.ccn}")
            if length > limits.length:
                exceeded.append(f"length {length} > {limits.length}")
            if params > limits.args:
                exceeded.append(f"parameters {params} > {limits.args}")
            if not exceeded:
                continue
            function = row[7]
            findings.append(
                Finding(
                    tool=self.name,
                    category=Category.COMPLEXITY,
                    rule_id="function-complexity",
                    severity=severity.complexity(ccn, length, params, limits),
                    title=f"{function} exceeds complexity limits",
                    message=f"{function}: {', '.join(exceeded)}",
                    file=rel_path(row[6], ctx.workdir),
                    line_start=start,
                    line_end=end,
                )
            )
        return Parsed(findings)
