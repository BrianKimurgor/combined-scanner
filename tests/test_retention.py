import os
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select, update

from scanner.db import repo
from scanner.db.models import FindingRow, Scan, UiSession
from scanner.db.session import session_scope
from scanner.retention import prune
from test_api import Env, build_env


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    yield build_env(tmp_path, monkeypatch)


def finished_scan(env: Env) -> str:
    response = env.upload()
    assert response.status_code == 202
    env.run_worker()
    return str(response.json()["scan_id"])


def age(env: Env, scan_id: str, days: int) -> None:
    with session_scope(env.factory) as session:
        session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(created_at=datetime.now(UTC) - timedelta(days=days))
        )


def backdate(path: Path, days: float) -> None:
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))


def scan_count(env: Env) -> int:
    with session_scope(env.factory) as session:
        return int(session.scalar(select(func.count()).select_from(Scan)) or 0)


def test_old_finished_scans_are_removed_with_their_reports_and_findings(env: Env) -> None:
    old, recent = finished_scan(env), finished_scan(env)
    age(env, old, 120)
    result = prune(env.settings, env.factory, days=90)
    assert result.scans == 1
    assert not (env.settings.reports_dir / old).exists()
    assert (env.settings.reports_dir / recent).is_dir()
    assert env.client.get(f"/scans/{old}", headers=env.headers).status_code == 404
    assert env.client.get(f"/scans/{recent}", headers=env.headers).status_code == 200
    with session_scope(env.factory) as session:
        remaining = set(session.scalars(select(FindingRow.scan_id)))
    assert remaining == {recent}


def test_dry_run_changes_nothing(env: Env) -> None:
    old = finished_scan(env)
    age(env, old, 120)
    assert prune(env.settings, env.factory, days=90, dry_run=True).scans == 1
    assert scan_count(env) == 1
    assert (env.settings.reports_dir / old).is_dir()


def test_waiting_and_running_scans_are_never_removed(env: Env) -> None:
    queued = str(env.upload().json()["scan_id"])
    age(env, queued, 400)
    assert prune(env.settings, env.factory, days=1).scans == 0
    assert (env.settings.uploads_dir / f"{queued}.zip").is_file()
    assert scan_count(env) == 1


def test_suppressions_and_baselines_outlive_the_scans(env: Env) -> None:
    scan_id = finished_scan(env)
    made = env.client.post(f"/scans/{scan_id}/baseline", json={"name": "keep"}, headers=env.headers)
    assert made.status_code == 201
    age(env, scan_id, 200)
    prune(env.settings, env.factory, days=90)
    assert [b["name"] for b in env.client.get("/baselines", headers=env.headers).json()] == ["keep"]


def test_expired_browser_sessions_are_removed(env: Env) -> None:
    with session_scope(env.factory) as session:
        owner = repo.authenticate(session, env.key)
        assert owner is not None
        repo.create_ui_session(session, owner.id, timedelta(seconds=-5))
        repo.create_ui_session(session, owner.id, timedelta(hours=1))
    assert prune(env.settings, env.factory).sessions == 1
    with session_scope(env.factory) as session:
        assert session.scalar(select(func.count()).select_from(UiSession)) == 1


def test_leftovers_are_cleaned_but_unrelated_files_are_not(env: Env) -> None:
    settings = env.settings
    stale_work = settings.work_dir / ("a" * 32)
    (stale_work / "src").mkdir(parents=True)
    fresh_work = settings.work_dir / ("b" * 32)
    fresh_work.mkdir()
    orphan_report = settings.reports_dir / ("c" * 32)
    orphan_report.mkdir()
    stranger = settings.work_dir / "notes.txt"
    stranger.write_text("mine", encoding="utf-8")
    partial = settings.uploads_dir / ("d" * 32 + ".part")
    partial.write_bytes(b"PK")
    for path in (stale_work, orphan_report, stranger, partial):
        backdate(path, 120 if path is orphan_report else 3)

    result = prune(settings, env.factory, days=90)

    assert result.leftovers == 3
    assert not stale_work.exists() and not orphan_report.exists() and not partial.exists()
    assert fresh_work.exists() and stranger.exists()


def test_a_running_scans_files_survive_even_when_old(env: Env) -> None:
    scan_id = str(env.upload().json()["scan_id"])
    upload = env.settings.uploads_dir / f"{scan_id}.zip"
    backdate(upload, 30)
    prune(env.settings, env.factory, days=90)
    assert upload.is_file()


def test_prune_command_reports_what_it_did(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from scanner.cli import app

    data = {"SCANNER_DATA_DIR": str(tmp_path / "data"), "SCANNER_SANDBOX": "local"}
    result = CliRunner().invoke(app, ["admin", "prune", "--dry-run"], env=data)
    assert result.exit_code == 0
    assert "would remove 0 scan(s)" in result.output
