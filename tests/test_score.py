from scanner.core.result import ToolStatus
from scanner.core.score import compute_score
from scanner.normalize.finding import Category, Finding, Severity
from scanner.plugins.base import Status

OK = ToolStatus(tool="a", status=Status.OK)


def _f(severity: Severity) -> Finding:
    return Finding(
        tool="t",
        category=Category.CODE,
        rule_id=f"R-{severity}",
        severity=severity,
        title="t",
        file="a.py",
        line_start=1,
    )


def test_no_findings_is_100_percent() -> None:
    score = compute_score([], [OK])
    assert score.percent == 100.0
    assert sum(score.points_lost.values()) == 0


def test_points_are_lost_per_severity() -> None:
    findings = [
        _f(Severity.CRITICAL),
        _f(Severity.HIGH),
        _f(Severity.MEDIUM),
        _f(Severity.LOW),
        _f(Severity.LOW),
    ]
    score = compute_score(findings, [OK])
    assert score.points_lost == {
        "critical": 10.0,
        "high": 5.0,
        "medium": 2.0,
        "low": 1.0,
        "info": 0.0,
    }
    assert score.percent == 82.0


def test_info_findings_are_free() -> None:
    assert compute_score([_f(Severity.INFO)] * 50, [OK]).percent == 100.0


def _in(category: Category, severity: Severity) -> Finding:
    return Finding(
        tool="t",
        category=category,
        rule_id=f"R-{category}-{severity}",
        severity=severity,
        title="t",
        file="a.py",
        line_start=1,
    )


def test_score_never_goes_below_zero() -> None:
    categories = [Category.DEPENDENCY, Category.SECRET, Category.CODE, Category.IAC]
    findings = [_in(c, Severity.CRITICAL) for c in categories for _ in range(20)]
    assert compute_score(findings, [OK]).percent == 0.0


def test_one_noisy_category_cannot_flatten_the_score() -> None:
    flood = [_in(Category.DUPLICATION, Severity.LOW) for _ in range(2000)]
    score = compute_score(flood, [OK])
    assert score.percent == 90.0  # duplication costs at most 10 points
    assert score.points_lost["low"] == 10.0


def test_caps_apply_per_category_and_keep_severity_totals_consistent() -> None:
    findings = [_in(Category.PII, Severity.HIGH) for _ in range(10)]  # 50 raw, capped at 10
    findings += [_in(Category.PII, Severity.LOW) for _ in range(100)]  # 50 raw
    findings.append(_in(Category.CODE, Severity.HIGH))  # not capped
    score = compute_score(findings, [OK])
    assert score.points_lost["high"] == 5.0 + 5.0  # pii high scaled to 5, plus the code finding
    assert score.points_lost["low"] == 5.0
    assert score.percent == 85.0
    assert score.category_caps["pii"] == 10.0


def test_no_scanner_ran_means_no_score() -> None:
    skipped = ToolStatus(tool="a", status=Status.SKIPPED)
    failed = ToolStatus(tool="b", status=Status.FAILED)
    assert compute_score([], [skipped, failed]).percent is None
    assert compute_score([], []).percent is None


def test_scanner_coverage_is_reported() -> None:
    skipped = ToolStatus(tool="b", status=Status.SKIPPED)
    score = compute_score([], [OK, skipped])
    assert (score.scanners_ok, score.scanners_total) == (1, 2)
