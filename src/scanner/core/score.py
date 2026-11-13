from collections import defaultdict
from collections.abc import Sequence

from scanner.core.result import HealthScore, ToolStatus
from scanner.normalize.finding import Category, Finding, Severity
from scanner.plugins.base import Status

# Points lost per finding. Info findings are free.
WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 5.0,
    Severity.MEDIUM: 2.0,
    Severity.LOW: 0.5,
    Severity.INFO: 0.0,
}

# A category can cost at most this many points, so thousands of low-value findings in one
# place (duplicated blocks, emails in test data) cannot flatten the whole score to 0%.
CATEGORY_CAPS: dict[Category, float] = {
    Category.DEPENDENCY: 40.0,
    Category.SECRET: 30.0,
    Category.CODE: 30.0,
    Category.IAC: 20.0,
    Category.LICENSE: 10.0,
    Category.PII: 10.0,
    Category.DUPLICATION: 10.0,
    Category.COMPLEXITY: 10.0,
}


def compute_score(findings: Sequence[Finding], tools: Sequence[ToolStatus]) -> HealthScore:
    ok = sum(1 for tool in tools if tool.status is Status.OK)
    raw: dict[Category, float] = defaultdict(float)
    for finding in findings:
        raw[finding.category] += WEIGHTS[finding.severity]
    # Scale every finding in an over-cap category so per-severity totals still add up.
    factor = {
        category: min(1.0, CATEGORY_CAPS[category] / points) if points else 1.0
        for category, points in raw.items()
    }
    lost = {severity.value: 0.0 for severity in Severity}
    for finding in findings:
        lost[finding.severity.value] += WEIGHTS[finding.severity] * factor[finding.category]
    lost = {key: round(value, 2) for key, value in lost.items()}
    percent = None if ok == 0 else round(max(0.0, 100.0 - sum(lost.values())), 1)
    return HealthScore(
        percent=percent,
        weights={severity.value: weight for severity, weight in WEIGHTS.items()},
        category_caps={category.value: cap for category, cap in CATEGORY_CAPS.items()},
        points_lost=lost,
        scanners_ok=ok,
        scanners_total=len(tools),
    )
