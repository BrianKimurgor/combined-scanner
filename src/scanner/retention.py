import logging
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from scanner.db import repo
from scanner.db.session import session_scope
from scanner.settings import Settings

logger = logging.getLogger(__name__)

BATCH = 500
LEFTOVER_GRACE = timedelta(days=1)  # working copies this old belong to no running scan
_OWNED_NAME = re.compile(r"^([0-9a-f]{32})(\.zip|\.part)?$")  # only ever touch our own names


@dataclass(frozen=True)
class PruneResult:
    scans: int = 0
    sessions: int = 0
    leftovers: int = 0


def _remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def _owned_entries(directory: Path) -> dict[Path, str]:
    if not directory.is_dir():
        return {}
    entries = {}
    for entry in directory.iterdir():
        match = _OWNED_NAME.match(entry.name)
        if match:
            entries[entry] = match.group(1)
    return entries


def _mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, UTC)


def _leftovers(
    settings: Settings, factory: sessionmaker[Session], cutoff: datetime, now: datetime
) -> list[Path]:
    """Files and folders no scan needs: from crashes, or from scans that were deleted."""
    stale: list[Path] = []
    with session_scope(factory) as session:
        for directory in (settings.work_dir, settings.uploads_dir):
            entries = _owned_entries(directory)
            busy = repo.existing_scan_ids(session, list(entries.values()), in_flight=True)
            stale += [
                p
                for p, sid in entries.items()
                if sid not in busy and _mtime(p) < now - LEFTOVER_GRACE
            ]
        reports = _owned_entries(settings.reports_dir)
        known = repo.existing_scan_ids(session, list(reports.values()), in_flight=False)
        stale += [p for p, sid in reports.items() if sid not in known and _mtime(p) < cutoff]
    return stale


def prune(
    settings: Settings,
    factory: sessionmaker[Session],
    *,
    days: int | None = None,
    now: datetime | None = None,
    dry_run: bool = False,
) -> PruneResult:
    """Delete finished scans older than the retention period, with their reports and leftovers."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=days if days is not None else settings.retention_days)
    scans = 0
    if dry_run:
        with session_scope(factory) as session:
            scans = repo.count_old_finished_scans(session, cutoff)
            sessions = repo.expired_ui_sessions(session, now)
        return PruneResult(scans, sessions, len(_leftovers(settings, factory, cutoff, now)))
    while True:
        with session_scope(factory) as session:
            ids = repo.old_finished_scan_ids(session, cutoff, BATCH)
            repo.delete_scans(session, ids)
        for scan_id in ids:
            shutil.rmtree(settings.reports_dir / scan_id, ignore_errors=True)
        scans += len(ids)
        if len(ids) < BATCH:
            break
    with session_scope(factory) as session:
        sessions = repo.delete_expired_ui_sessions(session, now)
    leftovers = _leftovers(settings, factory, cutoff, now)
    for path in leftovers:
        _remove(path)
    if scans or sessions or leftovers:
        logger.info(
            "retention: removed %d scan(s), %d session(s), %d leftover(s)",
            scans,
            sessions,
            len(leftovers),
        )
    return PruneResult(scans, sessions, len(leftovers))
