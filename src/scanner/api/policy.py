from datetime import date

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi import Path as PathParam
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError
from sqlalchemy.orm import Session, sessionmaker

from scanner.api.auth import OwnerDep, SessionDep
from scanner.api.routes import ScanId
from scanner.api.schemas import (
    BaselineCreate,
    BaselineOut,
    SuppressionCreate,
    SuppressionOut,
)
from scanner.core import baseline as baseline_module
from scanner.core.config import Suppression
from scanner.core.result import ScanReport
from scanner.db import repo
from scanner.db.models import BaselineRow, Scan, SuppressionRow
from scanner.db.repo import as_utc
from scanner.settings import Settings
from scanner.worker.runner import reapply_policy

router = APIRouter()


def _suppression_out(row: SuppressionRow) -> SuppressionOut:
    return SuppressionOut(
        id=row.id,
        scope=row.scope,
        fingerprint=row.fingerprint,
        reason=row.reason,
        expires=row.expires,
        created_at=as_utc(row.created_at),
        expired=row.expires < date.today(),
    )


def _baseline_out(row: BaselineRow) -> BaselineOut:
    return BaselineOut(
        id=row.id,
        name=row.name,
        source=row.source,
        size=row.size,
        created_at=as_utc(row.created_at),
    )


def _rejudge(request: Request, owner_id: int, scope: str, scan_ids: list[str]) -> None:
    """Re-evaluate the scans a changed suppression affects: the one in view and the latest."""
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    with factory() as session:
        latest = repo.latest_done_scan(session, owner_id, scope)
    for scan_id in dict.fromkeys([*scan_ids, *([latest.id] if latest else [])]):
        reapply_policy(settings, factory, scan_id)


@router.get("/suppressions", response_model=list[SuppressionOut])
def list_suppressions(owner: OwnerDep, session: SessionDep) -> list[SuppressionOut]:
    return [_suppression_out(r) for r in repo.list_suppressions(session, owner.id)]


@router.post("/suppressions", status_code=201, response_model=SuppressionOut)
async def create_suppression(
    request: Request, body: SuppressionCreate, owner: OwnerDep, session: SessionDep
) -> SuppressionOut:
    """Accept one finding of a scan until `expires`; later scans of the same source honour it."""
    scan = repo.get_scan(session, owner.id, body.scan_id)
    if scan is None or scan.source_ref is None:
        raise HTTPException(404, "scan not found")
    if body.expires <= date.today():
        raise HTTPException(422, "expires must be a future date")
    try:
        Suppression(fingerprint=body.fingerprint, reason=body.reason, expires=body.expires)
    except ValidationError as exc:
        raise HTTPException(422, exc.errors()[0]["msg"]) from exc
    if not repo.finding_fingerprint_exists(session, scan.id, body.fingerprint):
        raise HTTPException(404, "that finding is not in this scan")
    row = repo.upsert_suppression(
        session, owner.id, scan.source_ref, body.fingerprint, body.reason.strip(), body.expires
    )
    out = _suppression_out(row)
    session.commit()  # the re-evaluation below reads it through its own session
    await run_in_threadpool(_rejudge, request, owner.id, scan.source_ref, [scan.id])
    return out


@router.delete("/suppressions/{suppression_id}", status_code=204)
async def delete_suppression(
    request: Request,
    suppression_id: int,
    owner: OwnerDep,
    session: SessionDep,
) -> Response:
    row = repo.get_suppression(session, owner.id, suppression_id)
    if row is None:
        raise HTTPException(404, "suppression not found")
    scope = row.scope
    session.delete(row)
    session.commit()
    await run_in_threadpool(_rejudge, request, owner.id, scope, [])
    return Response(status_code=204)


@router.get("/baselines", response_model=list[BaselineOut])
def list_baselines(owner: OwnerDep, session: SessionDep) -> list[BaselineOut]:
    return [_baseline_out(r) for r in repo.list_baselines(session, owner.id)]


def _load_report(request: Request, scan: Scan) -> ScanReport:
    settings: Settings = request.app.state.settings
    path = settings.reports_dir / scan.id / "report.json"
    if not path.is_file():
        raise HTTPException(404, "report not found")
    return ScanReport.model_validate_json(path.read_bytes())


@router.post("/scans/{scan_id}/baseline", status_code=201, response_model=BaselineOut)
async def create_baseline(
    request: Request,
    scan_id: ScanId,
    body: BaselineCreate,
    owner: OwnerDep,
    session: SessionDep,
) -> BaselineOut:
    """Accept every current finding of a scan; scans that use it only fail on new ones."""
    scan = repo.get_scan(session, owner.id, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    if scan.status != "done" or scan.source_ref is None:
        raise HTTPException(409, f"scan is {scan.status}")
    report = await run_in_threadpool(_load_report, request, scan)
    try:
        row = repo.create_baseline(
            session,
            owner.id,
            body.name.strip(),
            scan.source_ref,
            baseline_module.from_report(report),
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _baseline_out(row)


@router.delete("/baselines/{baseline_id}", status_code=204)
def delete_baseline(
    baseline_id: int = PathParam(ge=1), *, owner: OwnerDep, session: SessionDep
) -> Response:
    row = repo.get_baseline(session, owner.id, baseline_id)
    if row is None:
        raise HTTPException(404, "baseline not found")
    session.delete(row)
    return Response(status_code=204)
