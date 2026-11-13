import json
from datetime import date, datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

from scanner.core.progress import ScanProgress, ToolProgress
from scanner.core.result import BaselineInfo, DiffInfo, GateResult, HealthScore, ToolStatus
from scanner.db.models import Scan
from scanner.db.repo import FindingFilter, as_utc
from scanner.normalize.finding import Category, Finding, Severity


class GitScanRequest(BaseModel):
    git_url: Annotated[str, StringConstraints(min_length=1, max_length=2048)]
    ref: Annotated[str, StringConstraints(min_length=1, max_length=200)] = "HEAD"
    # With base set, ref is the head: both revisions are scanned and only new findings gate.
    base: Annotated[str, StringConstraints(min_length=1, max_length=200)] | None = None
    baseline_id: int | None = None  # findings in this baseline are accepted
    # Also read every commit (up to the server's limit) for secrets; not with base.
    history: bool = False


class FindingQuery(BaseModel):
    """Query parameters for listing a scan's findings."""

    severity: Severity | None = None
    category: Category | None = None
    tool: str | None = None
    new: bool | None = Field(default=None, description="Diff scans: only findings new in the head")
    suppressed: bool | None = Field(default=None, description="Only suppressed, or only active")
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)

    def as_filter(self) -> FindingFilter:
        return FindingFilter(
            severity=self.severity.value if self.severity else None,
            category=self.category.value if self.category else None,
            tool=self.tool,
            is_new=self.new,
            suppressed=self.suppressed,
        )


class ScanCreated(BaseModel):
    scan_id: str
    status: str


class ScanStatus(BaseModel):
    id: str
    status: str
    source_type: str
    source: str | None
    scope: str | None = None  # what suppressions and trends are keyed on
    created_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None = None
    exit_code: int | None = None
    gate: GateResult | None = None
    score: HealthScore | None = None
    tools: list[ToolStatus] = Field(default_factory=list)
    finding_count: int | None = None
    counted_count: int | None = None  # findings that count: not suppressed, not already accepted
    suppressed_count: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    metrics: dict[str, float] = Field(default_factory=dict)
    base: str | None = None
    baseline_id: int | None = None
    history: bool = False
    diff: DiffInfo | None = None
    baseline: BaselineInfo | None = None
    notices: list[str] = Field(default_factory=list)
    progress: list[ToolProgress] = Field(default_factory=list)  # live, per scanner

    @classmethod
    def from_scan(cls, scan: Scan) -> "ScanStatus":
        summary = json.loads(scan.summary_json) if scan.summary_json else {}
        source = scan.source_ref
        if scan.source_type == "git":
            source = f"{scan.source_ref}@{scan.git_ref}"
        return cls(
            id=scan.id,
            status=scan.status,
            source_type=scan.source_type,
            source=source,
            scope=scan.source_ref,
            created_at=as_utc(scan.created_at),
            started_at=as_utc(scan.started_at),
            finished_at=as_utc(scan.finished_at),
            error=scan.error,
            exit_code=scan.exit_code,
            gate=summary.get("gate"),
            score=summary.get("score"),
            tools=summary.get("tools", []),
            finding_count=summary.get("finding_count"),
            counted_count=summary.get("counted_count"),
            suppressed_count=summary.get("suppressed_count", 0),
            by_severity=summary.get("by_severity", {}),
            by_category=summary.get("by_category", {}),
            metrics=summary.get("metrics", {}),
            base=scan.base_ref,
            baseline_id=scan.baseline_id,
            history=bool(scan.history),
            diff=summary.get("diff"),
            baseline=summary.get("baseline"),
            notices=summary.get("notices", []),
            progress=_progress(scan.progress_json),
        )


def _progress(raw: str | None) -> list[ToolProgress]:
    if not raw:
        return []
    try:
        return ScanProgress.model_validate_json(raw).tools
    except ValueError:
        return []


class ScanPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[ScanStatus]


class SourceInfo(BaseModel):
    source: str
    scans: int
    latest: datetime | None


class TrendPoint(BaseModel):
    scan_id: str
    at: datetime | None
    score_percent: float | None
    gate_passed: bool | None
    counted: int  # findings that count
    by_severity: dict[str, int]
    base: str | None = None


class Trend(BaseModel):
    source: str
    points: list[TrendPoint]


class SuppressionCreate(BaseModel):
    scan_id: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
    fingerprint: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")]
    reason: Annotated[str, StringConstraints(min_length=1, max_length=500)]
    expires: date


class SuppressionOut(BaseModel):
    id: int
    scope: str
    fingerprint: str
    reason: str
    expires: date
    created_at: datetime | None
    expired: bool


class BaselineCreate(BaseModel):
    name: Annotated[str, StringConstraints(min_length=1, max_length=100)]


class BaselineOut(BaseModel):
    id: int
    name: str
    source: str
    size: int
    created_at: datetime | None


class LoginRequest(BaseModel):
    api_key: Annotated[str, StringConstraints(min_length=1, max_length=200)]


class SessionInfo(BaseModel):
    name: str


class FindingsPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[Finding]
