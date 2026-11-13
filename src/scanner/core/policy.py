from collections.abc import Sequence
from datetime import date

from scanner.core.baseline import Baseline
from scanner.core.config import Config, Suppression
from scanner.core.gate import evaluate
from scanner.core.result import BaselineInfo, ScanReport
from scanner.core.score import compute_score
from scanner.normalize.finding import Finding, Suppressed


def _suppress(
    findings: list[Finding], suppressions: Sequence[Suppression], today: date
) -> list[str]:
    by_fingerprint = {s.fingerprint: s for s in suppressions}
    matched: set[str] = set()
    notices: list[str] = []
    for finding in findings:
        suppression = by_fingerprint.get(finding.fingerprint)
        if suppression is None:
            continue
        if suppression.fingerprint not in matched and suppression.expires < today:
            notices.append(
                f"Suppression {suppression.fingerprint} expired on {suppression.expires}; "
                "the finding counts again."
            )
        matched.add(suppression.fingerprint)
        if suppression.expires >= today:
            finding.suppressed = Suppressed(reason=suppression.reason, expires=suppression.expires)
    unused = [s for s in suppressions if s.fingerprint not in matched]
    if unused:
        notices.append(f"{len(unused)} suppression(s) matched no finding; remove them if obsolete.")
    return notices


def _apply_baseline(findings: list[Finding], baseline: Baseline | None) -> BaselineInfo | None:
    if baseline is None:
        return None
    known = set(baseline.fingerprints)
    for finding in findings:
        if finding.suppressed is not None:
            continue
        if finding.fingerprint in known:
            finding.is_new = False
        elif finding.is_new is None:
            finding.is_new = True
    active = [f for f in findings if f.suppressed is None]
    return BaselineInfo(
        source=baseline.source,
        created_at=baseline.created_at,
        size=len(known),
        new_count=sum(1 for f in active if f.is_new),
        existing_count=sum(1 for f in active if f.is_new is False),
    )


def _gate_metrics(
    metrics: dict[str, float], reference: dict[str, float] | None
) -> dict[str, float]:
    """Duplication only fails the gate when it got worse than the reference scan."""
    gated = dict(metrics)
    now, before = metrics.get("duplication_percent"), (reference or {}).get("duplication_percent")
    if now is not None and before is not None and now <= before:
        gated.pop("duplication_percent")
    return gated


def apply_policy(
    report: ScanReport,
    config: Config,
    *,
    suppressions: Sequence[Suppression] = (),
    baseline: Baseline | None = None,
    today: date | None = None,
) -> ScanReport:
    """Apply suppressions and a baseline, then recompute the gate and health score.

    Safe to run again on its own output, so reports can be re-judged after the rules change.
    """
    today = today or date.today()
    findings = [f.model_copy(deep=True) for f in report.findings]
    for finding in findings:
        finding.suppressed = None
        if report.diff is None:
            finding.is_new = None
    notices = _suppress(findings, suppressions, today)
    baseline_info = _apply_baseline(findings, baseline)

    active = [f for f in findings if f.suppressed is None]
    counted = [f for f in active if f.is_new is not False]
    reference = (
        report.diff.base_metrics if report.diff else (baseline.metrics if baseline else None)
    )
    diff = report.diff
    if diff is not None:
        diff = diff.model_copy(
            update={
                "new_count": sum(1 for f in active if f.is_new),
                "existing_count": sum(1 for f in active if f.is_new is False),
            }
        )
    return report.model_copy(
        update={
            "findings": findings,
            "gate": evaluate(counted, _gate_metrics(report.metrics, reference), config.gate),
            "score": compute_score(active, report.tools),
            "diff": diff,
            "baseline": baseline_info,
            "notices": notices,
        }
    )
