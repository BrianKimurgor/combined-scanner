import logging
import shutil
import time
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from scanner.core.baseline import Baseline
from scanner.core.config import Config
from scanner.core.policy import apply_policy
from scanner.core.progress import ScanProgress, waiting
from scanner.core.result import ScanReport, exit_code
from scanner.db import repo
from scanner.db.models import Scan
from scanner.db.session import session_scope
from scanner.ingest.errors import UnsafeInputError
from scanner.ingest.git_checkout import FetchOptions, git_checkout
from scanner.ingest.safe_extract import effective_root, safe_extract
from scanner.report import html as html_report
from scanner.report import json as json_report
from scanner.report import markdown as markdown_report
from scanner.report import sarif as sarif_report
from scanner.retention import prune
from scanner.settings import Settings
from scanner.worker.sandbox import (
    ProgressWatch,
    SandboxDirs,
    SandboxError,
    prepare_out_dir,
    run_in_sandbox,
)

logger = logging.getLogger(__name__)

MAX_REPORT_BYTES = 200 * 1024 * 1024
COMPLETED_EXIT_CODES = (0, 1, 2)  # pass, gate failed, a scanner failed; all produce a report


def _label(scan: Scan, ref: str | None = None) -> str:
    if scan.source_type == "git":
        return f"{scan.source_ref}@{ref or scan.git_ref}"
    return scan.source_ref or "uploaded zip"


def _progress_saver(factory: sessionmaker[Session], scan_id: str) -> Callable[[ScanProgress], None]:
    def save(progress: ScanProgress) -> None:
        with session_scope(factory) as session:
            repo.set_progress(session, scan_id, progress.model_dump_json())

    return save


def _fetch_git(settings: Settings, scan: Scan, workdir: Path) -> None:
    """Fetch the scanned revision into src, the base into base, and the history if asked."""
    options = FetchOptions(
        timeout=min(settings.scan_timeout_seconds, 600), limits=settings.extract_limits
    )
    head = options
    if scan.history:
        depth = settings.history_max_commits
        head = replace(options, depth=depth, history_dest=workdir / "history")
    git_checkout(scan.source_ref or "", scan.git_ref or "HEAD", workdir / "src", head)
    if scan.base_ref:
        git_checkout(scan.source_ref or "", scan.base_ref, workdir / "base", options)


def _scan_source(
    settings: Settings, factory: sessionmaker[Session], scan: Scan, workdir: Path
) -> ScanReport:
    src, out, base = workdir / "src", workdir / "out", workdir / "base"
    history = workdir / "history"  # only used by history scans
    workdir.mkdir(parents=True, exist_ok=True)
    if scan.source_type == "zip":
        safe_extract(settings.uploads_dir / f"{scan.id}.zip", src, settings.extract_limits)
    else:
        _fetch_git(settings, scan, workdir)
    prepare_out_dir(out)
    # Zips often wrap everything in one folder; git trees must be compared as they are.
    root = effective_root(src) if scan.source_type == "zip" else src
    base_root = base if scan.base_ref else None
    # Every scanner shows as waiting until the sandbox reports on it.
    tools = Config().scanners.enabled
    save_progress = _progress_saver(factory, scan.id)
    save_progress(waiting(tools, passes=2 if base_root else 1))
    watch = ProgressWatch(tools, save_progress)
    dirs = SandboxDirs(root, out, base_root, history if scan.history else None)
    result = run_in_sandbox(settings, scan.id, dirs, watch)
    if result.timed_out:
        raise SandboxError("the scan exceeded the time limit")
    if result.exit_code not in COMPLETED_EXIT_CODES:
        logger.error("scan %s: sandbox exited %s: %s", scan.id, result.exit_code, result.stderr)
        raise SandboxError("the scanner sandbox failed before producing a report")
    report_path = out / "report.json"
    if not report_path.is_file() or report_path.stat().st_size > MAX_REPORT_BYTES:
        raise SandboxError("the scanner did not produce a usable report")
    report = ScanReport.model_validate_json(report_path.read_bytes())
    # The server-side paths are meaningless to the user and should not leak.
    update: dict[str, object] = {"target": _label(scan)}
    if report.diff is not None:
        labels = {"base": _label(scan, scan.base_ref), "head": _label(scan)}
        update["diff"] = report.diff.model_copy(update=labels)
    return report.model_copy(update=update)


def _judge(factory: sessionmaker[Session], scan: Scan, report: ScanReport) -> ScanReport:
    """Apply this owner's suppressions for the source, and the scan's baseline if it has one."""
    baseline = None
    with session_scope(factory) as session:
        suppressions = repo.suppressions_for(session, scan.owner_id, scan.source_ref)
        if scan.baseline_id is not None:
            row = repo.get_baseline(session, scan.owner_id, scan.baseline_id)
            baseline = Baseline.model_validate_json(row.data) if row else None
    return apply_policy(report, Config(), suppressions=suppressions, baseline=baseline)


def reapply_policy(settings: Settings, factory: sessionmaker[Session], scan_id: str) -> None:
    """Re-judge a finished scan after its suppressions changed, without scanning again."""
    path = settings.reports_dir / scan_id / "report.json"
    if not path.is_file():
        return
    with factory() as session:
        scan = session.get(Scan, scan_id)
    if scan is None or scan.status != "done":
        return
    report = _judge(factory, scan, ScanReport.model_validate_json(path.read_bytes()))
    _store_report_files(settings, scan_id, report)
    with session_scope(factory) as session:
        repo.store_report(session, scan_id, report, exit_code(report))


def _store_report_files(settings: Settings, scan_id: str, report: ScanReport) -> None:
    target = settings.reports_dir / scan_id
    target.mkdir(parents=True, exist_ok=True)
    (target / "report.json").write_text(json_report.render(report), encoding="utf-8")
    (target / "report.md").write_text(markdown_report.render(report), encoding="utf-8")
    (target / "report.html").write_text(html_report.render(report), encoding="utf-8")
    (target / "report.sarif").write_text(sarif_report.render(report), encoding="utf-8")


def process_scan(settings: Settings, factory: sessionmaker[Session], scan: Scan) -> None:
    """Run one claimed scan to completion; uploads and working copies never outlive it."""
    workdir = settings.work_dir / scan.id
    started = time.monotonic()
    outcome = "done"
    findings = 0
    try:
        report = _judge(factory, scan, _scan_source(settings, factory, scan, workdir))
        _store_report_files(settings, scan.id, report)
        findings = len(report.findings)
        with session_scope(factory) as session:
            repo.store_report(session, scan.id, report, exit_code(report))
    except (UnsafeInputError, SandboxError) as exc:
        outcome = "failed"
        _fail(factory, scan.id, str(exc))
    except Exception:
        outcome = "failed"
        logger.exception("scan %s failed", scan.id)
        _fail(factory, scan.id, "internal error while scanning")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        (settings.uploads_dir / f"{scan.id}.zip").unlink(missing_ok=True)
        seconds = round(time.monotonic() - started, 1)
        logger.info(
            "scan %s %s in %.1fs",
            scan.id,
            outcome,
            seconds,
            extra={
                "scan_id": scan.id,
                "outcome": outcome,
                "seconds": seconds,
                "findings": findings,
            },
        )


def _fail(factory: sessionmaker[Session], scan_id: str, message: str) -> None:
    with session_scope(factory) as session:
        repo.fail_scan(session, scan_id, message)


def process_next(settings: Settings, factory: sessionmaker[Session]) -> bool:
    """Claim and process one queued scan; False when the queue is empty."""
    with factory() as session:
        scan = repo.claim_next_scan(session)
    if scan is None:
        return False
    process_scan(settings, factory, scan)
    return True


def run_worker(
    settings: Settings,
    factory: sessionmaker[Session],
    *,
    once: bool = False,
    should_stop: Callable[[], bool] = lambda: False,
) -> int:
    """Poll for scans until stopped (or, with once, until the queue is drained)."""
    with session_scope(factory) as session:
        recovered = repo.recover_stale(
            session, timedelta(seconds=settings.scan_timeout_seconds * 2)
        )
    if recovered:
        logger.warning("marked %d stale scan(s) as failed", recovered)
    processed = 0
    next_prune = 0.0
    while not should_stop():
        if not once and time.monotonic() >= next_prune:
            next_prune = time.monotonic() + settings.prune_interval_seconds
            try:
                prune(settings, factory)
            except Exception:
                logger.exception("retention pruning failed")
        if process_next(settings, factory):
            processed += 1
        elif once:
            break
        else:
            time.sleep(settings.poll_seconds)
    return processed
