from collections.abc import Sequence

from scanner.core.config import FailLevel, GateConfig
from scanner.core.result import GateResult
from scanner.normalize.finding import Category, Finding, Severity

_FAIL_ON_KEYS = {
    Category.DEPENDENCY: "vulnerability",
    Category.SECRET: "secret",
    Category.CODE: "code",
    Category.IAC: "iac",
    Category.PII: "pii",
}


def _min_rank(level: FailLevel) -> int | None:
    if level == "none":
        return None
    if level == "any":
        return Severity.INFO.rank
    return Severity(level).rank


def evaluate(
    findings: Sequence[Finding], metrics: dict[str, float], gate: GateConfig
) -> GateResult:
    reasons: list[str] = []
    for category, key in _FAIL_ON_KEYS.items():
        level: FailLevel = getattr(gate.fail_on, key)
        rank = _min_rank(level)
        if rank is None:
            continue
        count = sum(1 for f in findings if f.category is category and f.severity.rank >= rank)
        if count:
            reasons.append(f"{count} {key} finding(s) at or above '{level}'")
    complexity = sum(1 for f in findings if f.category is Category.COMPLEXITY)
    if complexity:
        reasons.append(f"{complexity} function(s) exceed the complexity limits")
    percent = metrics.get("duplication_percent")
    if percent is not None and percent > gate.duplication.max_percent:
        reasons.append(
            f"duplication {percent:.1f}% exceeds the {gate.duplication.max_percent:g}% limit"
        )
    return GateResult(passed=not reasons, reasons=reasons)
