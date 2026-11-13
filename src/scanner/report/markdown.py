from collections import Counter

from scanner.core.result import ScanReport
from scanner.normalize.finding import Finding, Severity
from scanner.report.mdutil import code_span, escape_text


def _cell(value: object) -> str:
    return escape_text(value)


def _location(finding: Finding) -> str:
    if not finding.file:
        return "-"
    where = f"{finding.file}:{finding.line_start}" if finding.line_start else finding.file
    return f"{where} (commit {finding.commit[:8]})" if finding.commit else where


def _table(header: list[str], rows: list[list[object]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return lines


def _score_line(report: ScanReport) -> str:
    score = report.score
    if score.percent is None:
        return "- Health score: **n/a** (no scanner ran successfully)"
    gap = round(100 - score.percent, 1)
    coverage = f"based on {score.scanners_ok} of {score.scanners_total} scanners"
    if score.scanners_ok < score.scanners_total:
        coverage += "; skipped or failed scanners may hide more findings"
    remaining = f"{gap:g} points from 100%" if gap else "nothing left to fix"
    return f"- Health score: **{score.percent:g}%** ({remaining}; {coverage})"


def _diff_lines(report: ScanReport) -> list[str]:
    lines: list[str] = []
    diff = report.diff
    if diff is not None:
        lines += [
            f"- Compared: {code_span(diff.base)} to {code_span(diff.head)}, "
            f"{diff.changed_total} changed file(s)",
            f"- New findings: {diff.new_count}, existing: {diff.existing_count}, "
            f"fixed: {diff.fixed_count}",
        ]
    baseline = report.baseline
    if baseline is not None:
        lines.append(
            f"- Baseline: {baseline.size} recorded; new {baseline.new_count}, "
            f"already accepted {baseline.existing_count}"
        )
    if report.suppressed_count():
        lines.append(
            f"- Suppressed: {report.suppressed_count()} (accepted until their review date)"
        )
    return lines


def render(report: ScanReport) -> str:
    shown = report.new_findings()  # in diff mode only the findings this change introduced
    lines = _header(report)
    lines += _warnings(report)
    lines += _scanners(report)
    lines += _summary(report, shown)
    lines += _findings(report, shown)
    return "\n".join(lines).rstrip() + "\n"


def _header(report: ScanReport) -> list[str]:
    verdict = "PASSED" if report.gate.passed else "FAILED"
    return [
        "# Code Scan Report",
        "",
        f"- Target: {code_span(report.target)}",
        f"- Scanned: {report.started_at:%Y-%m-%d %H:%M:%S} UTC ({report.duration_seconds:.1f}s)",
        f"- Quality gate: **{verdict}**",
        _score_line(report),
        *_diff_lines(report),
        "",
    ]


def _warnings(report: ScanReport) -> list[str]:
    lines: list[str] = []
    if not report.any_scanner_ran():
        lines += [
            "> **Warning:** no scanner ran successfully, so this result is not meaningful.",
            "",
        ]
    if report.gate.reasons:
        lines += ["## Gate failures", "", *[f"- {reason}" for reason in report.gate.reasons], ""]
    if report.notices:
        lines += ["## Notices", "", *[f"- {escape_text(n)}" for n in report.notices], ""]
    return lines


def _scanners(report: ScanReport) -> list[str]:
    return [
        "## Scanners",
        "",
        *_table(
            ["Tool", "Status", "Findings", "Duration", "Details"],
            [
                [t.tool, t.status.value, t.finding_count, f"{t.duration_seconds:.1f}s", t.message]
                for t in report.tools
            ],
        ),
    ]


def _summary(report: ScanReport, shown: list[Finding]) -> list[str]:
    by_severity = Counter(f.severity.value for f in shown)
    lines = ["", "## Summary", ""]
    lines += _table(
        ["Severity", "Count"],
        [[s.value, by_severity.get(s.value, 0)] for s in Severity],
    )
    for key, value in report.metrics.items():
        lines.append(f"\n- {key}: {value:g}")
    return lines


def _findings(report: ScanReport, shown: list[Finding]) -> list[str]:
    """One table per category."""
    lines = ["", "## New findings" if (report.diff or report.baseline) else "## Findings", ""]
    if not shown:
        lines.append("No new findings." if (report.diff or report.baseline) else "No findings.")
    for category in sorted({f.category for f in shown}):
        group = [f for f in shown if f.category == category]
        lines += [f"### {category.value} ({len(group)})", ""]
        lines += _table(
            ["Severity", "Sources", "Rule", "Location", "Message", "Fingerprint"],
            [
                [
                    f.severity.value,
                    ", ".join(f.sources),
                    f.rule_id,
                    _location(f),
                    f.message or f.title,
                    f.fingerprint,
                ]
                for f in group
            ],
        )
        lines.append("")
    return lines
