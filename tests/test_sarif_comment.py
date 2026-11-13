import json
from datetime import UTC, datetime
from typing import Any

from scanner import __version__
from scanner.core.result import ChangedFile, DiffInfo, GateResult, ScanReport, ToolStatus
from scanner.core.score import compute_score
from scanner.normalize.finding import SECRET_MASK, Category, Finding, Severity
from scanner.plugins.base import Status
from scanner.report import comment, markdown, sarif
from scanner.report import html as html_report


def _finding(**overrides: Any) -> Finding:
    fields: dict[str, Any] = {
        "tool": "semgrep",
        "category": Category.CODE,
        "rule_id": "python.sql-injection",
        "severity": Severity.HIGH,
        "title": "sql injection",
        "message": "raw SQL",
        "file": "app/my db.py",
        "line_start": 7,
        "line_end": 9,
    }
    return Finding(**{**fields, **overrides})


def _report(
    findings: list[Finding], *, diff: bool = False, tools: list[ToolStatus] | None = None
) -> ScanReport:
    tools = tools or [ToolStatus(tool="semgrep", status=Status.OK, finding_count=len(findings))]
    new = [f for f in findings if f.is_new] if diff else findings
    reasons = [f"{len(new)} code finding(s) at or above 'high'"] if new else []
    info = None
    if diff:
        info = DiffInfo(
            base="main",
            head="feature",
            changed_files=[ChangedFile(path="a.py", status="modified")],
            changed_total=1,
            new_count=len(new),
            existing_count=len(findings) - len(new),
            fixed_count=2,
        )
    return ScanReport(
        target="repo",
        started_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        duration_seconds=1.0,
        tools=tools,
        findings=findings,
        gate=GateResult(passed=not new, reasons=reasons),
        score=compute_score(findings, tools),
        diff=info,
    )


def test_sarif_has_the_required_structure() -> None:
    doc = json.loads(sarif.render(_report([_finding()])))
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-schema-2.1.0.json")
    (run,) = doc["runs"]
    assert run["tool"]["driver"]["name"] == "code-scanner"
    assert run["tool"]["driver"]["version"] == __version__
    (result,) = run["results"]
    assert result["ruleId"] == "semgrep/python.sql-injection"
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
    assert result["level"] == "error"
    assert result["message"]["text"] == "raw SQL"
    assert result["partialFingerprints"]["codeScanner/v1"]


def test_sarif_locations_use_relative_encoded_uris_and_regions() -> None:
    (result,) = json.loads(sarif.render(_report([_finding()])))["runs"][0]["results"]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "app/my%20db.py", "uriBaseId": "%SRCROOT%"}
    assert physical["region"] == {"startLine": 7, "endLine": 9}


def test_sarif_without_a_line_has_no_region_and_without_a_file_no_location() -> None:
    findings = [
        _finding(line_start=None, line_end=None),
        _finding(file=None, line_start=None, rule_id="other"),
    ]
    first, second = json.loads(sarif.render(_report(findings)))["runs"][0]["results"]
    assert "region" not in first["locations"][0]["physicalLocation"]
    assert "locations" not in second


def test_sarif_levels_and_security_severity() -> None:
    severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    findings = [_finding(severity=s, rule_id=f"r-{s.value}") for s in severities]
    run = json.loads(sarif.render(_report(findings)))["runs"][0]
    assert [r["level"] for r in run["results"]] == ["error", "error", "warning", "note", "note"]
    scores = [r["properties"]["security-severity"] for r in run["tool"]["driver"]["rules"]]
    assert scores == ["9.5", "8.0", "5.5", "3.0", "0.0"]


def test_sarif_rules_are_deduplicated() -> None:
    findings = [_finding(line_start=1), _finding(line_start=2), _finding(rule_id="other")]
    run = json.loads(sarif.render(_report(findings)))["runs"][0]
    assert len(run["results"]) == 3 and len(run["tool"]["driver"]["rules"]) == 2


def test_sarif_in_diff_mode_contains_only_new_findings() -> None:
    findings = [_finding(is_new=True), _finding(rule_id="old", is_new=False)]
    results = json.loads(sarif.render(_report(findings, diff=True)))["runs"][0]["results"]
    assert [r["ruleId"] for r in results] == ["semgrep/python.sql-injection"]
    assert results[0]["properties"]["isNew"] is True


def test_sarif_reports_scanner_failures() -> None:
    tools = [ToolStatus(tool="trivy", status=Status.TIMEOUT, message="timed out after 600s")]
    (invocation,) = json.loads(sarif.render(_report([], tools=tools)))["runs"][0]["invocations"]
    assert invocation["executionSuccessful"] is False
    assert "trivy: timed out" in invocation["toolExecutionNotifications"][0]["message"]["text"]


def test_sarif_never_carries_secret_values() -> None:
    secret = _finding(
        category=Category.SECRET,
        tool="gitleaks",
        rule_id="aws",
        message="Possible secret",
        secret_masked=SECRET_MASK,
    )
    assert "AKIA" not in sarif.render(_report([secret]))


def test_comment_summarises_a_diff() -> None:
    findings = [_finding(is_new=True), _finding(rule_id="old", is_new=False)]
    text = comment.render(_report(findings, diff=True))
    assert text.startswith(comment.MARKER)
    assert "1 new finding(s), quality gate failed" in text
    assert "`main` to `feature`, 1 changed file(s)" in text
    assert "1 existing finding(s) not shown, 2 fixed" in text
    assert "`python.sql-injection`" in text and "`app/my db.py:7`" in text
    assert "`old`" not in text  # existing findings are not repeated


def test_comment_for_a_clean_change() -> None:
    text = comment.render(_report([_finding(is_new=False)], diff=True))
    assert "0 new finding(s), quality gate passed" in text and "No new findings." in text


def test_comment_neutralises_hostile_text() -> None:
    hostile = _finding(
        is_new=True,
        message="ping @octocat <img src=x onerror=alert(1)> [click](https://evil.example) | a\nb",
        rule_id="r|1",
    )
    text = comment.render(_report([hostile], diff=True))
    assert "<img" not in text and "@octocat" not in text and "[click](" not in text
    assert "https://evil" not in text and "&lt;img" in text
    assert text.count("\n") == len(text.splitlines())  # one finding stays on one table row
    assert "`r\\|1`" in text  # a pipe in a rule id cannot split the table cell
    row = next(line for line in text.splitlines() if line.startswith("| high"))
    assert row.count("|") - row.count("\\|") == 5  # four columns, no extra cells


def test_comment_limits_rows_and_size() -> None:
    many = [_finding(is_new=True, rule_id=f"r{n}", message="x" * 500) for n in range(60)]
    text = comment.render(_report(many, diff=True))
    assert text.count("\n| high") == comment.MAX_ROWS
    assert "…and 35 more" in text
    huge = [_finding(is_new=True, rule_id=f"r{n}", message="y" * 5000) for n in range(200)]
    assert len(comment.render(_report(huge, diff=True))) < 65_536


def test_comment_lists_scanner_problems_and_warns_when_nothing_ran() -> None:
    tools = [ToolStatus(tool="osv", status=Status.FAILED, message="exit code 3: boom")]
    text = comment.render(_report([], tools=tools))
    assert "Scanner problems" in text and "`osv`" in text and "no scanner ran successfully" in text


def test_markdown_report_escapes_hostile_text_and_shows_the_diff() -> None:
    hostile = _finding(is_new=True, message="hi @octocat <b>x</b>")
    text = markdown.render(_report([hostile, _finding(rule_id="old", is_new=False)], diff=True))
    assert "@octocat" not in text and "<b>" not in text
    assert "Compared: `main` to `feature`" in text
    assert "New findings: 1, existing: 1, fixed: 2" in text
    assert "## New findings" in text and "`old`" not in text and "| old |" not in text


def test_html_report_embeds_diff_data_without_breaking_out() -> None:
    findings = [
        _finding(is_new=True, message="</script><script>alert(1)</script>"),
        _finding(rule_id="old", is_new=False),
    ]
    page = html_report.render(_report(findings, diff=True))
    assert "</script><script>alert(1)" not in page
    document = page.split('type="application/json">', 1)[1].split("</script>", 1)[0]
    data = json.loads(document)
    assert data["diff"]["new_count"] == 1 and data["findings"][0]["is_new"] is True
