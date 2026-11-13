import json
import re
from datetime import UTC, datetime

from scanner.core.result import GateResult, ScanReport, ToolStatus
from scanner.core.score import compute_score
from scanner.normalize.finding import Category, Finding, Severity, Snippet
from scanner.plugins.base import Status
from scanner.report import html as html_report
from scanner.report import json as json_report
from scanner.report import markdown as markdown_report


def _report(passed: bool = False) -> ScanReport:
    finding = Finding(
        tool="semgrep",
        category=Category.CODE,
        rule_id="r|1",
        severity=Severity.HIGH,
        title="t",
        message="line one\nline two",
        file="app.py",
        line_start=4,
    )
    tools = [
        ToolStatus(tool="semgrep", status=Status.OK, finding_count=1),
        ToolStatus(tool="trivy", status=Status.SKIPPED, message="trivy not found on PATH"),
    ]
    return ScanReport(
        target="/work/project",
        started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        duration_seconds=1.5,
        tools=tools,
        findings=[finding],
        metrics={"duplication_percent": 2.5},
        gate=GateResult(passed=passed, reasons=[] if passed else ["1 code finding(s)"]),
        score=compute_score([finding], tools),
    )


def test_json_round_trip() -> None:
    report = _report()
    assert ScanReport.model_validate_json(json_report.render(report)) == report


def test_markdown_sections() -> None:
    text = markdown_report.render(_report())
    assert "# Code Scan Report" in text
    assert "**FAILED**" in text
    assert "## Gate failures" in text
    assert "| semgrep | ok | 1 |" in text
    assert "trivy not found on PATH" in text
    assert "### code (1)" in text
    assert "app.py:4" in text
    assert "duplication_percent: 2.5" in text


def test_markdown_escapes_table_cells() -> None:
    text = markdown_report.render(_report())
    assert "r\\|1" in text
    assert "line one line two" in text


def test_markdown_passed_and_empty() -> None:
    report = _report(passed=True)
    report.findings = []
    text = markdown_report.render(report)
    assert "**PASSED**" in text
    assert "## Gate failures" not in text
    assert "No findings." in text


def _embedded(text: str) -> dict[str, object]:
    match = re.search(r'<script id="report-data"[^>]*>(.*?)</script>', text, re.DOTALL)
    assert match
    return json.loads(match.group(1))  # type: ignore[no-any-return]


def test_html_embeds_the_report() -> None:
    report = _report()
    text = html_report.render(report)
    assert text.startswith("<!doctype html>")
    assert _embedded(text) == json.loads(report.model_dump_json())


def test_html_neutralises_hostile_finding_text() -> None:
    report = _report()
    payload = "</script><img src=x onerror=alert(1)>&\u2028"
    report.findings[0].message = payload
    text = html_report.render(report)
    assert "</script><img" not in text
    assert "<img" not in text
    assert _embedded(text)["findings"][0]["message"] == payload  # type: ignore[index]


def test_html_csp_allows_only_the_nonce() -> None:
    text = html_report.render(_report())
    nonce = re.search(r"script-src 'nonce-([^']+)'", text)
    assert nonce
    assert "default-src 'none'" in text
    assert "unsafe-inline" not in text
    assert text.count(nonce.group(1)) == 5  # two CSP directives, style tag and two script tags
    assert "__NONCE__" not in text
    assert "__DATA__" not in text
    assert html_report.render(_report()) != text  # fresh nonce per render


def test_markdown_shows_health_score_and_coverage() -> None:
    text = markdown_report.render(_report())
    assert "Health score: **95%** (5 points from 100%; based on 1 of 2 scanners" in text
    assert "may hide more findings" in text


def test_markdown_score_is_na_when_nothing_ran() -> None:
    report = _report()
    report.score = compute_score([], [])
    assert "Health score: **n/a**" in markdown_report.render(report)


def test_html_embeds_the_score() -> None:
    score = _embedded(html_report.render(_report()))["score"]
    assert score["percent"] == 95.0  # type: ignore[index]
    assert score["scanners_ok"] == 1  # type: ignore[index]


def test_html_never_uses_innerhtml() -> None:
    assert "innerHTML" not in html_report.render(_report())


def test_html_supports_light_and_dark_themes() -> None:
    text = html_report.render(_report())
    assert 'data-theme="dark"' in text
    assert "prefers-color-scheme: dark" in text
    assert "scanner-report-theme" in text


def test_html_embeds_snippets_for_the_detail_panel() -> None:
    report = _report()
    report.findings[0].snippet = Snippet(
        start_line=3, lines=["a", "</script>b"], highlight_start=4, highlight_end=4
    )
    text = html_report.render(report)
    assert "</script>b" not in text
    finding = _embedded(text)["findings"][0]  # type: ignore[index]
    assert finding["snippet"]["lines"] == ["a", "</script>b"]
