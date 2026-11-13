from typing import Annotated

from fastapi import APIRouter, HTTPException, Query

from scanner.api.auth import OwnerDep, SessionDep
from scanner.api.schemas import ScanPage, ScanStatus, SourceInfo, Trend, TrendPoint
from scanner.db import repo
from scanner.db.repo import as_utc

router = APIRouter()

STATUSES = {"queued", "running", "done", "failed"}


@router.get("/scans", response_model=ScanPage)
def list_scans(
    owner: OwnerDep,
    session: SessionDep,
    status: str | None = None,
    source: Annotated[str | None, Query(max_length=2200)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ScanPage:
    """Your scans, newest first."""
    if status is not None and status not in STATUSES:
        raise HTTPException(422, f"status must be one of {', '.join(sorted(STATUSES))}")
    total, rows = repo.list_scans(
        session, owner.id, status=status, source=source, limit=limit, offset=offset
    )
    return ScanPage(
        total=total,
        limit=limit,
        offset=offset,
        items=[ScanStatus.from_scan(scan) for scan in rows],
    )


@router.get("/sources", response_model=list[SourceInfo])
def list_sources(owner: OwnerDep, session: SessionDep) -> list[SourceInfo]:
    """Every project (upload name or git URL) you have scanned."""
    return [
        SourceInfo(source=source, scans=count, latest=as_utc(latest))
        for source, count, latest in repo.list_sources(session, owner.id)
    ]


@router.get("/trends", response_model=Trend)
def get_trend(
    owner: OwnerDep,
    session: SessionDep,
    source: Annotated[str, Query(min_length=1, max_length=2200)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> Trend:
    """Health score and finding counts over time for one source."""
    points = []
    for scan in repo.trend_scans(session, owner.id, source, limit):
        status = ScanStatus.from_scan(scan)
        points.append(
            TrendPoint(
                scan_id=scan.id,
                at=status.finished_at or status.created_at,
                score_percent=scan.score_percent,
                gate_passed=scan.gate_passed,
                counted=status.counted_count or 0,
                by_severity=status.by_severity,
                base=scan.base_ref,
            )
        )
    return Trend(source=source, points=points)
