from pathlib import Path
from typing import Any

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
from scanner.plugins.history import history_env, history_repo, in_commit


class GitleaksPlugin(ScannerPlugin):
    name = "gitleaks"
    binary = "gitleaks"

    def _report(self, ctx: ScanContext) -> str:
        return str(ctx.plugin_dir(self.name) / "report.json")

    def build_command(self, ctx: ScanContext) -> list[str]:
        output = [
            "--report-format",
            "json",
            "--report-path",
            self._report(ctx),
            "--redact",
            "--exit-code",
            "0",
            "--no-banner",
        ]
        repo = history_repo(ctx)
        if repo is not None:
            # Every line ever added in any commit, which includes everything committed now.
            return ["gitleaks", "git", repo, *output]
        return ["gitleaks", "detect", "--no-git", "--source", ".", *output]

    def command_env(self, ctx: ScanContext) -> dict[str, str]:
        return history_env(ctx, self.name)

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        report = Path(self._report(ctx))
        if not report.is_file():
            return Parsed([])
        text = report.read_text(encoding="utf-8")
        return Parsed([self._finding(ctx, item) for item in load_json(text, []) or []])

    def _finding(self, ctx: ScanContext, item: dict[str, Any]) -> Finding:
        # Only whitelisted fields are read. Secret and Match hold the secret, and in history mode
        # Author, Email and Message describe a person, so none of them is kept.
        rule_id = str(item["RuleID"])
        commit = str(item["Commit"]) if item.get("Commit") else None
        return Finding(
            tool=self.name,
            category=Category.SECRET,
            rule_id=rule_id,
            severity=Severity.HIGH,
            title=str(item.get("Description") or rule_id),
            message=in_commit(f"Possible secret detected by rule {rule_id}", commit),
            file=rel_path(str(item["File"]), ctx.workdir),
            line_start=to_line(item.get("StartLine")),
            line_end=to_line(item.get("EndLine")),
            secret_masked=SECRET_MASK,
            commit=commit,
        )
