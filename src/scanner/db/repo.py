import hashlib
import json
import secrets
import uuid
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, cast

from sqlalchemy import delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from scanner.core.baseline import Baseline
from scanner.core.config import Suppression
from scanner.core.result import ScanReport
from scanner.db.models import (
    ApiKey,
    BaselineRow,
    FindingRow,
    Scan,
    SuppressionRow,
    UiSession,
    utcnow,
)

KEY_PREFIX = "cs_"


def _rowcount(result: object) -> int:
    return int(cast("CursorResult[Any]", result).rowcount or 0)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; everything stored here is UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def create_api_key(session: Session, name: str) -> str:
    """Return a new key once; only its hash is stored."""
    if session.scalar(select(ApiKey.id).where(ApiKey.name == name)) is not None:
        raise ValueError(f"an API key named {name!r} already exists")
    key = KEY_PREFIX + secrets.token_urlsafe(32)
    session.add(ApiKey(name=name, key_hash=hash_key(key)))
    try:
        session.flush()
    except IntegrityError as exc:
        session.rollback()
        raise ValueError(f"an API key named {name!r} already exists") from exc
    return key


def authenticate(session: Session, key: str) -> ApiKey | None:
    row = session.scalar(select(ApiKey).where(ApiKey.key_hash == hash_key(key)))
    return row if row is not None and not row.revoked else None


def count_recent_scans(session: Session, owner_id: int, since: datetime) -> int:
    stmt = (
        select(func.count())
        .select_from(Scan)
        .where(Scan.owner_id == owner_id, Scan.created_at >= since)
    )
    return int(session.scalar(stmt) or 0)


def count_queued(session: Session) -> int:
    return int(
        session.scalar(select(func.count()).select_from(Scan).where(Scan.status == "queued")) or 0
    )


@dataclass(frozen=True)
class NewScan:
    """What a queued scan should look at."""

    source_type: str  # zip | git
    source_ref: str | None  # the upload's name, or the git URL
    git_ref: str | None = None
    base_ref: str | None = None  # set for diff scans
    baseline_id: int | None = None  # findings in this baseline are accepted
    history: bool = False  # git scans: also read every commit for secrets


def create_scan(session: Session, owner_id: int, new: NewScan, scan_id: str | None = None) -> Scan:
    scan = Scan(
        id=scan_id or uuid.uuid4().hex,
        owner_id=owner_id,
        status="queued",
        source_type=new.source_type,
        source_ref=new.source_ref,
        git_ref=new.git_ref,
        base_ref=new.base_ref,
        baseline_id=new.baseline_id,
        history=new.history,
    )
    session.add(scan)
    session.flush()
    return scan


def get_scan(session: Session, owner_id: int, scan_id: str) -> Scan | None:
    """Scans are only visible to the key that created them."""
    return session.scalar(select(Scan).where(Scan.id == scan_id, Scan.owner_id == owner_id))


def claim_next_scan(session: Session) -> Scan | None:
    """Atomically move the oldest queued scan to running; safe with several workers."""
    for _ in range(5):
        scan_id = session.scalar(
            select(Scan.id).where(Scan.status == "queued").order_by(Scan.created_at).limit(1)
        )
        if scan_id is None:
            return None
        claimed = session.execute(
            update(Scan)
            .where(Scan.id == scan_id, Scan.status == "queued")
            .values(status="running", started_at=utcnow())
        )
        session.commit()
        if _rowcount(claimed) == 1:  # a competing worker that won the row leaves 0 here
            return session.get(Scan, scan_id)
    return None


def set_progress(session: Session, scan_id: str, progress_json: str) -> None:
    """Record per-scanner progress; ignored once the scan has finished."""
    session.execute(
        update(Scan)
        .where(Scan.id == scan_id, Scan.status == "running")
        .values(progress_json=progress_json)
    )


def fail_scan(session: Session, scan_id: str, error: str) -> None:
    session.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(status="failed", error=error[:2000], finished_at=utcnow())
    )


def recover_stale(session: Session, older_than: timedelta) -> int:
    """Mark scans stuck in 'running' (the worker died) as failed."""
    cutoff = utcnow() - older_than
    result = session.execute(
        update(Scan)
        .where(Scan.status == "running", Scan.started_at < cutoff)
        .values(
            status="failed",
            error="the worker stopped before finishing this scan",
            finished_at=utcnow(),
        )
    )
    return _rowcount(result)


def store_report(session: Session, scan_id: str, report: ScanReport, exit_code: int) -> None:
    """Record a finished scan, replacing any findings stored by an earlier evaluation."""
    counted = report.new_findings()
    summary = {
        "tools": [t.model_dump(mode="json") for t in report.tools],
        "gate": report.gate.model_dump(mode="json"),
        "metrics": report.metrics,
        "by_severity": dict(Counter(f.severity.value for f in counted)),
        "by_category": dict(Counter(f.category.value for f in counted)),
        "score": report.score.model_dump(mode="json"),
        "finding_count": len(report.findings),
        "counted_count": len(counted),
        "suppressed_count": report.suppressed_count(),
        "diff": report.diff.model_dump(mode="json") if report.diff else None,
        "baseline": report.baseline.model_dump(mode="json") if report.baseline else None,
        "notices": report.notices,
    }
    session.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
    session.add_all(
        FindingRow(
            scan_id=scan_id,
            position=index,
            severity=finding.severity.value,
            category=finding.category.value,
            is_new=finding.is_new,
            suppressed=finding.suppressed is not None,
            fingerprint=finding.fingerprint,
            sources="," + ",".join(finding.sources) + ",",
            data=finding.model_dump_json(),
        )
        for index, finding in enumerate(report.findings)
    )
    session.execute(
        update(Scan)
        .where(Scan.id == scan_id)
        .values(
            status="done",
            finished_at=func.coalesce(Scan.finished_at, utcnow()),
            exit_code=exit_code,
            gate_passed=report.gate.passed,
            score_percent=report.score.percent,
            summary_json=json.dumps(summary),
        )
    )


@dataclass(frozen=True)
class FindingFilter:
    """Optional conditions on a scan's findings; None means any value."""

    severity: str | None = None
    category: str | None = None
    tool: str | None = None  # must already be validated against the registry
    is_new: bool | None = None
    suppressed: bool | None = None


def list_findings(
    session: Session,
    scan_id: str,
    filters: FindingFilter | None = None,
    *,
    limit: int = 100,
    offset: int = 0,
) -> tuple[int, Sequence[str]]:
    """Return (total, finding JSON strings) for one scan."""
    f = filters or FindingFilter()
    conditions = [FindingRow.scan_id == scan_id]
    if f.suppressed is not None:
        flagged = FindingRow.suppressed.is_(True)
        conditions.append(flagged if f.suppressed else ~flagged)
    if f.is_new is not None:
        conditions.append(FindingRow.is_new == f.is_new)
    if f.severity:
        conditions.append(FindingRow.severity == f.severity)
    if f.category:
        conditions.append(FindingRow.category == f.category)
    if f.tool:
        conditions.append(FindingRow.sources.like(f"%,{f.tool},%"))
    total = int(
        session.scalar(select(func.count()).select_from(FindingRow).where(*conditions)) or 0
    )
    rows = session.scalars(
        select(FindingRow.data)
        .where(*conditions)
        .order_by(FindingRow.position)
        .limit(limit)
        .offset(offset)
    ).all()
    return total, rows


def list_scans(
    session: Session,
    owner_id: int,
    *,
    status: str | None = None,
    source: str | None = None,
    limit: int = 25,
    offset: int = 0,
) -> tuple[int, Sequence[Scan]]:
    conditions = [Scan.owner_id == owner_id]
    if status:
        conditions.append(Scan.status == status)
    if source:
        conditions.append(Scan.source_ref == source)
    total = int(session.scalar(select(func.count()).select_from(Scan).where(*conditions)) or 0)
    rows = session.scalars(
        select(Scan).where(*conditions).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return total, rows


def list_sources(session: Session, owner_id: int) -> Sequence[tuple[str, int, datetime]]:
    """Every source the owner has scanned, with scan count and latest scan time."""
    rows = session.execute(
        select(Scan.source_ref, func.count(), func.max(Scan.created_at))
        .where(Scan.owner_id == owner_id, Scan.source_ref.is_not(None))
        .group_by(Scan.source_ref)
        .order_by(func.max(Scan.created_at).desc())
    ).all()
    return [(str(source), int(count), latest) for source, count, latest in rows]


def trend_scans(session: Session, owner_id: int, source: str, limit: int = 100) -> Sequence[Scan]:
    """The most recent finished scans of one source, oldest first."""
    newest = session.scalars(
        select(Scan)
        .where(Scan.owner_id == owner_id, Scan.source_ref == source, Scan.status == "done")
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ).all()
    return list(reversed(newest))


def latest_done_scan(session: Session, owner_id: int, source: str) -> Scan | None:
    return session.scalar(
        select(Scan)
        .where(Scan.owner_id == owner_id, Scan.source_ref == source, Scan.status == "done")
        .order_by(Scan.created_at.desc())
        .limit(1)
    )


def finding_fingerprint_exists(session: Session, scan_id: str, fingerprint: str) -> bool:
    return (
        session.scalar(
            select(FindingRow.id)
            .where(FindingRow.scan_id == scan_id, FindingRow.fingerprint == fingerprint)
            .limit(1)
        )
        is not None
    )


def upsert_suppression(
    session: Session,
    owner_id: int,
    scope: str,
    fingerprint: str,
    reason: str,
    expires: date,
) -> SuppressionRow:
    row = session.scalar(
        select(SuppressionRow).where(
            SuppressionRow.owner_id == owner_id,
            SuppressionRow.scope == scope,
            SuppressionRow.fingerprint == fingerprint,
        )
    )
    if row is None:
        row = SuppressionRow(
            owner_id=owner_id, scope=scope, fingerprint=fingerprint, reason=reason, expires=expires
        )
        session.add(row)
    else:
        row.reason, row.expires = reason, expires
    session.flush()
    return row


def list_suppressions(session: Session, owner_id: int) -> Sequence[SuppressionRow]:
    return session.scalars(
        select(SuppressionRow)
        .where(SuppressionRow.owner_id == owner_id)
        .order_by(SuppressionRow.expires, SuppressionRow.id)
    ).all()


def get_suppression(session: Session, owner_id: int, suppression_id: int) -> SuppressionRow | None:
    return session.scalar(
        select(SuppressionRow).where(
            SuppressionRow.id == suppression_id, SuppressionRow.owner_id == owner_id
        )
    )


def suppressions_for(session: Session, owner_id: int, scope: str | None) -> list[Suppression]:
    """The owner's suppressions for one source, as the objects the policy step understands."""
    if scope is None:
        return []
    rows = session.scalars(
        select(SuppressionRow).where(
            SuppressionRow.owner_id == owner_id, SuppressionRow.scope == scope
        )
    ).all()
    # Rows bypass the max-lifetime check on purpose: it only applies when a rule is created.
    return [
        Suppression.model_construct(fingerprint=r.fingerprint, reason=r.reason, expires=r.expires)
        for r in rows
    ]


def create_baseline(
    session: Session, owner_id: int, name: str, source: str, baseline: Baseline
) -> BaselineRow:
    if session.scalar(
        select(BaselineRow.id).where(BaselineRow.owner_id == owner_id, BaselineRow.name == name)
    ):
        raise ValueError(f"a baseline named {name!r} already exists")
    row = BaselineRow(
        owner_id=owner_id,
        name=name,
        source=source,
        size=len(baseline.fingerprints),
        data=baseline.model_dump_json(),
    )
    session.add(row)
    session.flush()
    return row


def list_baselines(session: Session, owner_id: int) -> Sequence[BaselineRow]:
    return session.scalars(
        select(BaselineRow).where(BaselineRow.owner_id == owner_id).order_by(BaselineRow.id.desc())
    ).all()


def get_baseline(session: Session, owner_id: int, baseline_id: int) -> BaselineRow | None:
    return session.scalar(
        select(BaselineRow).where(BaselineRow.id == baseline_id, BaselineRow.owner_id == owner_id)
    )


def create_ui_session(session: Session, owner_id: int, lifetime: timedelta) -> str:
    """Return a new cookie token once; only its hash is stored."""
    token = secrets.token_urlsafe(32)
    session.add(
        UiSession(owner_id=owner_id, token_hash=hash_key(token), expires_at=utcnow() + lifetime)
    )
    session.flush()
    return token


def authenticate_session(session: Session, token: str) -> ApiKey | None:
    row = session.scalar(select(UiSession).where(UiSession.token_hash == hash_key(token)))
    if row is None:
        return None
    expires = as_utc(row.expires_at)
    if expires is None or expires <= utcnow():
        session.delete(row)
        return None
    owner = session.get(ApiKey, row.owner_id)
    return owner if owner is not None and not owner.revoked else None


def delete_ui_session(session: Session, token: str) -> None:
    session.execute(delete(UiSession).where(UiSession.token_hash == hash_key(token)))


def list_api_keys(session: Session) -> list[tuple[ApiKey, int, datetime | None]]:
    """Every key with how many scans it has made and when it last scanned."""
    rows = session.execute(
        select(ApiKey, func.count(Scan.id), func.max(Scan.created_at))
        .outerjoin(Scan, Scan.owner_id == ApiKey.id)
        .group_by(ApiKey.id)
        .order_by(ApiKey.id)
    ).all()
    return [(key, int(count), as_utc(last)) for key, count, last in rows]


def _named_key(session: Session, name: str) -> ApiKey:
    key = session.scalar(select(ApiKey).where(ApiKey.name == name))
    if key is None:
        raise ValueError(f"no API key named {name!r}")
    return key


def revoke_api_key(session: Session, name: str) -> None:
    """Stop the key and end every browser login made with it."""
    key = _named_key(session, name)
    key.revoked = True
    session.execute(delete(UiSession).where(UiSession.owner_id == key.id))


def rotate_api_key(session: Session, name: str) -> str:
    """Replace a key's secret; its scans, suppressions and baselines stay with it."""
    key = _named_key(session, name)
    if key.revoked:
        raise ValueError(f"the key {name!r} is revoked")
    new_key = KEY_PREFIX + secrets.token_urlsafe(32)
    key.key_hash = hash_key(new_key)
    session.execute(delete(UiSession).where(UiSession.owner_id == key.id))
    return new_key


def old_finished_scan_ids(session: Session, cutoff: datetime, limit: int = 500) -> list[str]:
    return list(
        session.scalars(
            select(Scan.id)
            .where(Scan.status.in_(("done", "failed")), Scan.created_at < cutoff)
            .order_by(Scan.created_at)
            .limit(limit)
        )
    )


def count_old_finished_scans(session: Session, cutoff: datetime) -> int:
    stmt = (
        select(func.count())
        .select_from(Scan)
        .where(Scan.status.in_(("done", "failed")), Scan.created_at < cutoff)
    )
    return int(session.scalar(stmt) or 0)


def delete_scans(session: Session, scan_ids: Sequence[str]) -> None:
    session.execute(delete(FindingRow).where(FindingRow.scan_id.in_(scan_ids)))
    session.execute(delete(Scan).where(Scan.id.in_(scan_ids)))


def existing_scan_ids(session: Session, candidates: Sequence[str], *, in_flight: bool) -> set[str]:
    """Which of these ids are scans; with in_flight, only those still queued or running."""
    found: set[str] = set()
    for start in range(0, len(candidates), 500):
        stmt = select(Scan.id).where(Scan.id.in_(candidates[start : start + 500]))
        if in_flight:
            stmt = stmt.where(Scan.status.in_(("queued", "running")))
        found.update(session.scalars(stmt))
    return found


def expired_ui_sessions(session: Session, now: datetime) -> int:
    stmt = select(func.count()).select_from(UiSession).where(UiSession.expires_at <= now)
    return int(session.scalar(stmt) or 0)


def delete_expired_ui_sessions(session: Session, now: datetime) -> int:
    return _rowcount(session.execute(delete(UiSession).where(UiSession.expires_at <= now)))


@dataclass(frozen=True)
class MetricsSnapshot:
    by_status: dict[str, int]
    gate_failed: int
    oldest_queued: datetime | None
    durations: list[float]
    keys_active: int


def metrics_snapshot(session: Session) -> MetricsSnapshot:
    """Counters for the metrics endpoint, read from the database so every process agrees."""
    by_status = dict(session.execute(select(Scan.status, func.count()).group_by(Scan.status)).all())
    gate_failed = session.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.status == "done", Scan.gate_passed.is_(False))
    )
    oldest_queued = session.scalar(select(func.min(Scan.created_at)).where(Scan.status == "queued"))
    recent = session.execute(
        select(Scan.started_at, Scan.finished_at)
        .where(Scan.status == "done", Scan.started_at.is_not(None), Scan.finished_at.is_not(None))
        .order_by(Scan.created_at.desc())
        .limit(1000)
    ).all()
    durations = [
        (finished - started).total_seconds()
        for s, f in recent
        if (started := as_utc(s)) is not None and (finished := as_utc(f)) is not None
    ]
    return MetricsSnapshot(
        by_status={k: int(v) for k, v in by_status.items()},
        gate_failed=int(gate_failed or 0),
        oldest_queued=as_utc(oldest_queued),
        durations=durations,
        keys_active=int(
            session.scalar(
                select(func.count()).select_from(ApiKey).where(ApiKey.revoked.is_(False))
            )
            or 0
        ),
    )
