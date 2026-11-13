from pathlib import Path

from scanner.normalize import severity
from scanner.normalize.finding import Category, Finding
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    ScanContext,
    ScannerPlugin,
    load_json,
    rel_path,
    to_line,
)


class SemgrepPlugin(ScannerPlugin):
    name = "semgrep"
    binary = "semgrep"
    env = {"SEMGREP_SEND_METRICS": "off"}

    def skip_reason(self, ctx: ScanContext) -> str | None:
        # Rule packs such as p/default are downloaded, so offline runs need rule files on disk.
        if ctx.config.offline and not all(
            Path(r).exists() for r in ctx.config.scanners.semgrep_rules
        ):
            return "offline mode needs local semgrep rules (--semgrep-rules PATH)"
        return None

    def build_command(self, ctx: ScanContext) -> list[str]:
        configs = [arg for rule in ctx.config.scanners.semgrep_rules for arg in ("--config", rule)]
        return [
            "semgrep",
            "scan",
            *configs,
            "--jobs",
            str(ctx.config.scanners.semgrep_jobs),
            "--json",
            "--metrics=off",
            "--quiet",
            "--disable-version-check",
            ".",
        ]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        data = load_json(proc.stdout, {})
        findings: list[Finding] = []
        for item in data.get("results") or []:
            extra = item.get("extra", {})
            rule_id = str(item["check_id"])
            message = str(extra.get("message", ""))
            findings.append(
                Finding(
                    tool=self.name,
                    category=Category.CODE,
                    rule_id=rule_id,
                    severity=severity.lookup(severity.SEMGREP, extra.get("severity")),
                    title=rule_id.rsplit(".", 1)[-1],
                    message=message,
                    file=rel_path(str(item["path"]), ctx.workdir),
                    line_start=to_line(item.get("start", {}).get("line")),
                    line_end=to_line(item.get("end", {}).get("line")),
                )
            )
        return Parsed(findings)
