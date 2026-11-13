from collections import Counter
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from scanner.normalize.finding import Finding
from scanner.plugins.base import Status


class ToolStatus(BaseModel):
    tool: str
    status: Status
    message: str = ""
    duration_seconds: float = 0.0
    finding_count: int = 0


class GateResult(BaseModel):
    passed: bool
    reasons: list[str] = Field(default_factory=list)


class HealthScore(BaseModel):
    """100% means no findings above info; None means no scanner ran, so nothing is known."""

    percent: float | None
    weights: dict[str, float]
    category_caps: dict[str, float] = Field(default_factory=dict)
    points_lost: dict[str, float]
    scanners_ok: int
    scanners_total: int


class ChangedFile(BaseModel):
    path: str
    status: Literal["added", "modified", "deleted"]


class DiffInfo(BaseModel):
    base: str
    head: str
    changed_files: list[ChangedFile]
    changed_total: int  # changed_files may be truncated
    new_count: int
    existing_count: int
    fixed_count: int
    base_metrics: dict[str, float] = Field(default_factory=dict)


class BaselineInfo(BaseModel):
    source: str
    created_at: datetime
    size: int  # findings recorded in the baseline
    new_count: int
    existing_count: int


class ScanReport(BaseModel):
    target: str
    started_at: datetime
    duration_seconds: float
    tools: list[ToolStatus]
    findings: list[Finding]
    metrics: dict[str, float] = Field(default_factory=dict)
    gate: GateResult
    score: HealthScore
    diff: DiffInfo | None = None
    baseline: BaselineInfo | None = None
    notices: list[str] = Field(default_factory=list)

    def count_by(self, attribute: str) -> dict[str, int]:
        counts = Counter(str(getattr(f, attribute)) for f in self.findings)
        return dict(counts)

    def new_findings(self) -> list[Finding]:
        """The findings that count: not suppressed, and not already in the base or baseline."""
        return [f for f in self.findings if f.suppressed is None and f.is_new is not False]

    def suppressed_count(self) -> int:
        return sum(1 for f in self.findings if f.suppressed is not None)

    def any_scanner_ran(self) -> bool:
        return any(t.status is Status.OK for t in self.tools)


def exit_code(report: ScanReport) -> int:
    """0 = pass, 1 = gate failed, 2 = a scanner failed or timed out, or none ran at all."""
    if not report.gate.passed:
        return 1
    if not report.any_scanner_ran():
        return 2
    if any(t.status in (Status.FAILED, Status.TIMEOUT) for t in report.tools):
        return 2
    return 0
