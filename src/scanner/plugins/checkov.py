from typing import Any

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


class CheckovPlugin(ScannerPlugin):
    name = "checkov"
    binary = "checkov"
    ok_exit_codes = frozenset({0, 1})  # 1 = failed checks

    def build_command(self, ctx: ScanContext) -> list[str]:
        # Secrets are covered by gitleaks, so that framework is skipped.
        return [
            "checkov",
            "--skip-framework",
            "secrets",
            "--directory",
            ".",
            "--output",
            "json",
            "--quiet",
            "--skip-download",
        ]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        data: Any = load_json(proc.stdout, [])
        reports = data if isinstance(data, list) else [data]  # one report per framework
        findings: list[Finding] = []
        for report in reports:
            for check in report.get("results", {}).get("failed_checks") or []:
                rule_id = str(check["check_id"])
                line_range = check.get("file_line_range") or [None, None]
                resource = check.get("resource")
                title = str(check.get("check_name") or rule_id)
                findings.append(
                    Finding(
                        tool=self.name,
                        category=Category.IAC,
                        rule_id=rule_id,
                        severity=severity.lookup(severity.CHECKOV, check.get("severity")),
                        title=title,
                        message=f"{title} (resource: {resource})" if resource else title,
                        file=rel_path(str(check["file_path"]), ctx.workdir),
                        line_start=to_line(line_range[0]),
                        line_end=to_line(line_range[1]),
                    )
                )
        return Parsed(findings)
