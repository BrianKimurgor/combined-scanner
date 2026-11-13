from pathlib import Path

from scanner.normalize.finding import SECRET_MASK, Category, Finding, Severity
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    ScanContext,
    ScannerPlugin,
    load_json,
    rel_path,
    to_line,
)


class GitleaksPlugin(ScannerPlugin):
    name = "gitleaks"
    binary = "gitleaks"

    def _report(self, ctx: ScanContext) -> str:
        return str(ctx.plugin_dir(self.name) / "report.json")

    def build_command(self, ctx: ScanContext) -> list[str]:
        return [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            ".",
            "--report-format",
            "json",
            "--report-path",
            self._report(ctx),
            "--redact",
            "--exit-code",
            "0",
            "--no-banner",
        ]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        report = Path(self._report(ctx))
        if not report.is_file():
            return Parsed([])
        text = report.read_text(encoding="utf-8")
        findings: list[Finding] = []
        # Only whitelisted fields are read; Secret/Match are dropped so no secret is retained.
        for item in load_json(text, []) or []:
            rule_id = str(item["RuleID"])
            findings.append(
                Finding(
                    tool=self.name,
                    category=Category.SECRET,
                    rule_id=rule_id,
                    severity=Severity.HIGH,
                    title=str(item.get("Description") or rule_id),
                    message=f"Possible secret detected by rule {rule_id}",
                    file=rel_path(str(item["File"]), ctx.workdir),
                    line_start=to_line(item.get("StartLine")),
                    line_end=to_line(item.get("EndLine")),
                    secret_masked=SECRET_MASK,
                )
            )
        return Parsed(findings)
