from scanner.core.result import ScanReport
from scanner.normalize.finding import Finding
from scanner.plugins.base import Status
from scanner.report.mdutil import code_span, escape_text

MARKER = "<!-- code-scanner:pr-comment -->"  # lets a CI job find and update its previous comment
MAX_ROWS = 25
MAX_CHARS = 60_000  # GitHub rejects comments over 65,536 characters


def _location(finding: Finding) -> str:
    if not finding.file:
        return "-"
    return code_span(f"{finding.file}:{finding.line_start}" if finding.line_start else finding.file)


def render(report: ScanReport) -> str:
    new = report.new_findings()
    diff = report.diff
    verdict = "passed" if report.gate.passed else "failed"
    if diff or report.baseline:
        title = f"Code scan: {len(new)} new finding(s), quality gate {verdict}"
    else:
        title = f"Code scan: {len(new)} finding(s), quality gate {verdict}"
    lines = [MARKER, f"## {title}", ""]

    facts = []
    if diff:
        facts.append(
            f"{code_span(diff.base)} to {code_span(diff.head)}, "
            f"{diff.changed_total} changed file(s)"
        )
        facts.append(
            f"{diff.existing_count} existing finding(s) not shown, {diff.fixed_count} fixed"
        )
    if report.baseline:
        facts.append(f"{report.baseline.existing_count} finding(s) in the baseline not shown")
    if report.suppressed_count():
        facts.append(f"{report.suppressed_count()} suppressed")
    if report.score.percent is not None:
        facts.append(f"health score {report.score.percent:g}%")
    if facts:
        lines += [" · ".join(facts), ""]

    if not report.any_scanner_ran():
        lines += [
            "> **Warning:** no scanner ran successfully, so this result is not meaningful.",
            "",
        ]
    if report.gate.reasons:
        lines += [*[f"- {escape_text(reason)}" for reason in report.gate.reasons], ""]
    if report.notices:
        lines += [*[f"> {escape_text(notice)}" for notice in report.notices], ""]
    problems = [t for t in report.tools if t.status in (Status.FAILED, Status.TIMEOUT)]
    if problems:
        lines += ["**Scanner problems**", ""]
        lines += [
            f"- {code_span(t.tool)}: {escape_text(t.message or t.status.value)}" for t in problems
        ]
        lines.append("")

    if new:
        lines += ["| Severity | Rule | Location | Finding |", "|---|---|---|---|"]
        for finding in new[:MAX_ROWS]:
            lines.append(
                f"| {finding.severity.value} | {code_span(finding.rule_id)} | {_location(finding)} "
                f"| {escape_text(finding.message or finding.title)} |"
            )
        if len(new) > MAX_ROWS:
            lines += ["", f"…and {len(new) - MAX_ROWS} more. See the full report for the rest."]
    else:
        lines.append("No new findings.")
    text = "\n".join(lines).rstrip() + "\n"
    return (
        text if len(text) <= MAX_CHARS else text[:MAX_CHARS].rsplit("\n", 1)[0] + "\n\n…truncated\n"
    )
