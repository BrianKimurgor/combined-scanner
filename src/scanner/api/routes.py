import os
import re
import uuid
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as PathParam
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session, sessionmaker
from starlette.datastructures import UploadFile

from scanner.api.auth import OwnerDep, SessionDep
from scanner.api.schemas import (
    FindingQuery,
    FindingsPage,
    GitScanRequest,
    ScanCreated,
    ScanStatus,
)
from scanner.db import repo
from scanner.db.models import Scan, utcnow
from scanner.db.session import session_scope
from scanner.ingest.errors import UnsafeInputError
from scanner.ingest.git_checkout import validate_git_url, validate_ref
from scanner.normalize.finding import Finding
from scanner.plugins import REGISTRY
from scanner.settings import Settings

router = APIRouter()

MIB = 1024 * 1024
ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")  # a normal archive, or an empty one
ScanId = Annotated[str, PathParam(pattern=r"^[0-9a-f]{32}$")]


class ReportFormat(StrEnum):
    JSON = "json"
    MD = "md"
    HTML = "html"
    SARIF = "sarif"


MEDIA_TYPES = {
    ReportFormat.JSON: "application/json",
    ReportFormat.MD: "text/markdown; charset=utf-8",
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.SARIF: "application/sarif+json",
}


def _check_quota(factory: sessionmaker[Session], settings: Settings, owner_id: int) -> None:
    with session_scope(factory) as session:
        since = utcnow() - timedelta(hours=1)
        if repo.count_recent_scans(session, owner_id, since) >= settings.max_scans_per_hour:
            raise HTTPException(
                429, "scan limit reached; try again later", headers={"Retry-After": "3600"}
            )
        if repo.count_queued(session) >= settings.max_queued_scans:
            raise HTTPException(
                503, "the scan queue is full; try again later", headers={"Retry-After": "300"}
            )


def _validate_git(body: GitScanRequest) -> None:
    try:
        validate_git_url(body.git_url)
        validate_ref(body.ref)
        if body.base is not None:
            validate_ref(body.base)
    except UnsafeInputError as exc:
        raise HTTPException(400, str(exc)) from exc
    if body.history and body.base is not None:
        raise HTTPException(400, "history cannot be combined with base")


def _enqueue(
    factory: sessionmaker[Session], owner_id: int, scan_id: str, new: repo.NewScan
) -> None:
    with session_scope(factory) as session:
        baseline = new.baseline_id
        if baseline is not None and repo.get_baseline(session, owner_id, baseline) is None:
            raise HTTPException(400, "unknown baseline")
        repo.create_scan(session, owner_id, new, scan_id)


def _display_name(filename: str | None) -> str:
    name = re.sub(r"[^\w.\- ]", "_", Path(filename or "").name)[:100]
    return name or "upload.zip"


async def _save_upload(
    request: Request, settings: Settings, scan_id: str
) -> tuple[str, int | None]:
    form = await request.form(max_files=1, max_fields=4)
    try:
        upload = form.get("file")
        if not isinstance(upload, UploadFile):
            raise HTTPException(400, "multipart field 'file' with a zip archive is required")
        raw_baseline = form.get("baseline_id")
        if isinstance(raw_baseline, str) and raw_baseline.strip() and not raw_baseline.isdigit():
            raise HTTPException(400, "baseline_id must be a number")
        baseline_id = int(raw_baseline) if isinstance(raw_baseline, str) and raw_baseline else None
        settings.uploads_dir.mkdir(parents=True, exist_ok=True)
        final = settings.uploads_dir / f"{scan_id}.zip"
        partial = final.with_suffix(".part")
        size = 0
        try:
            with partial.open("wb") as out:
                while chunk := await upload.read(MIB):
                    if size == 0 and not chunk.startswith(ZIP_MAGIC):
                        raise HTTPException(400, "the upload is not a zip archive")
                    size += len(chunk)
                    if size > settings.max_upload_bytes:
                        raise HTTPException(413, "the upload is larger than the allowed size")
                    out.write(chunk)
            if size == 0:
                raise HTTPException(400, "the upload is empty")
            os.replace(partial, final)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
        return _display_name(upload.filename), baseline_id
    finally:
        await form.close()


@router.post("/scans", status_code=202, response_model=ScanCreated)
async def create_scan(request: Request, owner: OwnerDep) -> ScanCreated:
    """Queue a scan: a zip upload (multipart `file`) or JSON `{git_url, ref}`; `base` diffs."""
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    await run_in_threadpool(_check_quota, factory, settings, owner.id)
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    scan_id = uuid.uuid4().hex
    if content_type == "multipart/form-data":
        name, baseline_id = await _save_upload(request, settings, scan_id)
        new = repo.NewScan("zip", name, baseline_id=baseline_id)
    elif content_type == "application/json":
        try:
            body = GitScanRequest.model_validate(await request.json())
        except ValueError as exc:
            raise HTTPException(422, "body must be JSON with git_url and optional ref") from exc
        await run_in_threadpool(_validate_git, body)
        new = repo.NewScan(
            "git", body.git_url, body.ref, body.base, body.baseline_id, history=body.history
        )
    else:
        raise HTTPException(415, "send a multipart zip upload or a JSON git request")
    try:
        await run_in_threadpool(_enqueue, factory, owner.id, scan_id, new)
    except BaseException:
        (settings.uploads_dir / f"{scan_id}.zip").unlink(missing_ok=True)
        raise
    return ScanCreated(scan_id=scan_id, status="queued")


def _owned_scan(session: Session, owner_id: int, scan_id: str) -> Scan:
    scan = repo.get_scan(session, owner_id, scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan


@router.get("/scans/{scan_id}", response_model=ScanStatus)
def get_scan(scan_id: ScanId, owner: OwnerDep, session: SessionDep) -> ScanStatus:
    return ScanStatus.from_scan(_owned_scan(session, owner.id, scan_id))


@router.get("/scans/{scan_id}/findings", response_model=FindingsPage)
def get_findings(
    scan_id: ScanId,
    owner: OwnerDep,
    session: SessionDep,
    query: Annotated[FindingQuery, Query()],
) -> FindingsPage:
    if query.tool is not None and query.tool not in REGISTRY:
        raise HTTPException(422, f"unknown tool; expected one of {', '.join(sorted(REGISTRY))}")
    scan = _owned_scan(session, owner.id, scan_id)
    if scan.status != "done":
        raise HTTPException(409, f"scan is {scan.status}")
    total, rows = repo.list_findings(
        session, scan.id, query.as_filter(), limit=query.limit, offset=query.offset
    )
    return FindingsPage(
        total=total,
        limit=query.limit,
        offset=query.offset,
        items=[Finding.model_validate_json(r) for r in rows],
    )


@router.get("/scans/{scan_id}/report")
def get_report(
    request: Request,
    scan_id: ScanId,
    owner: OwnerDep,
    session: SessionDep,
    fmt: Annotated[ReportFormat, Query(alias="format")] = ReportFormat.JSON,
) -> Response:
    scan = _owned_scan(session, owner.id, scan_id)
    if scan.status != "done":
        raise HTTPException(409, f"scan is {scan.status}")
    settings: Settings = request.app.state.settings
    path = settings.reports_dir / scan.id / f"report.{fmt.value}"
    if not path.is_file():
        raise HTTPException(404, "report not found")
    headers = _report_headers(fmt, scan.id)
    return Response(path.read_bytes(), media_type=MEDIA_TYPES[fmt], headers=headers)


def _report_headers(fmt: ReportFormat, scan_id: str) -> dict[str, str]:
    if fmt is ReportFormat.HTML:
        # Scanned code can put arbitrary text in a report, so the page runs in an opaque origin:
        # its script cannot reach this site's cookies or API, and only our own pages may frame it.
        return {
            "Content-Security-Policy": "sandbox allow-scripts; frame-ancestors 'self'",
            "X-Frame-Options": "SAMEORIGIN",
        }
    return {"Content-Disposition": f'attachment; filename="scan-{scan_id}.{fmt.value}"'}


@router.get("/healthz", include_in_schema=False)
def healthz() -> dict[str, str]:
    return {"status": "ok"}
