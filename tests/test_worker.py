import json
import uuid
import zipfile
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from fakes import GoodPlugin
from scanner.db import repo
from scanner.db.models import Scan, utcnow
from scanner.db.session import init_db, make_engine, make_session_factory, session_scope
from scanner.settings import Settings
from scanner.worker import runner
from scanner.worker.sandbox import SandboxDirs, SandboxResult, docker_command


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path / "data", sandbox_mode="local", max_upload_bytes=5 * 1024 * 1024
    )


@pytest.fixture
def factory(settings: Settings) -> sessionmaker[Session]:
    engine = make_engine(settings)
    init_db(engine)
    for directory in (settings.uploads_dir, settings.work_dir, settings.reports_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return make_session_factory(engine)


@pytest.fixture
def owner_id(factory: sessionmaker[Session]) -> int:
    with session_scope(factory) as session:
        key = repo.create_api_key(session, "tester")
        owner = repo.authenticate(session, key)
        assert owner is not None
        return owner.id


@pytest.fixture(autouse=True)
def fake_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scanner.worker.sandbox.build_plugins", lambda names: [GoodPlugin()])


def _queue_zip(
    settings: Settings, factory: sessionmaker[Session], owner_id: int, *entries: tuple[str, str]
) -> str:
    scan_id = uuid.uuid4().hex
    with zipfile.ZipFile(settings.uploads_dir / f"{scan_id}.zip", "w") as zf:
        for name, text in entries:
            zf.writestr(name, text)
    with session_scope(factory) as session:
        repo.create_scan(session, owner_id, repo.NewScan("zip", "project.zip"), scan_id)
    return scan_id


def _scan(factory: sessionmaker[Session], scan_id: str) -> Scan:
    with factory() as session:
        scan = session.get(Scan, scan_id)
        assert scan is not None
        return scan


def test_api_keys_are_stored_hashed(factory: sessionmaker[Session]) -> None:
    with session_scope(factory) as session:
        key = repo.create_api_key(session, "alice")
    with factory() as session:
        assert repo.authenticate(session, key) is not None
        assert repo.authenticate(session, key + "x") is None
        stored = session.execute(text("select key_hash from api_keys")).scalar_one()
    assert key not in stored and stored == repo.hash_key(key)


def test_revoked_and_duplicate_keys(factory: sessionmaker[Session]) -> None:
    with session_scope(factory) as session:
        key = repo.create_api_key(session, "alice")
        with pytest.raises(ValueError, match="already exists"):
            repo.create_api_key(session, "alice")
    with session_scope(factory) as session:
        owner = repo.authenticate(session, key)
        assert owner is not None
        owner.revoked = True
    with factory() as session:
        assert repo.authenticate(session, key) is None


def test_queue_is_fifo_and_each_scan_is_claimed_once(
    factory: sessionmaker[Session], owner_id: int
) -> None:
    with session_scope(factory) as session:
        first = repo.create_scan(session, owner_id, repo.NewScan("zip", "a.zip"))
        second = repo.create_scan(session, owner_id, repo.NewScan("zip", "b.zip"))
    with factory() as one, factory() as two:
        claimed_one = repo.claim_next_scan(one)
        claimed_two = repo.claim_next_scan(two)
        assert repo.claim_next_scan(one) is None
    assert claimed_one is not None and claimed_two is not None
    assert [claimed_one.id, claimed_two.id] == [first.id, second.id]
    assert claimed_one.status == "running" and claimed_one.started_at is not None


def test_stale_running_scans_are_failed(factory: sessionmaker[Session], owner_id: int) -> None:
    with session_scope(factory) as session:
        scan = repo.create_scan(session, owner_id, repo.NewScan("zip", "a.zip"))
        scan.status, scan.started_at = "running", utcnow() - timedelta(hours=3)
        fresh = repo.create_scan(session, owner_id, repo.NewScan("zip", "b.zip"))
        fresh.status, fresh.started_at = "running", utcnow()
    with session_scope(factory) as session:
        assert repo.recover_stale(session, timedelta(hours=1)) == 1
    assert _scan(factory, scan.id).status == "failed"
    assert _scan(factory, fresh.id).status == "running"


def test_zip_scan_runs_to_completion_and_cleans_up(
    settings: Settings, factory: sessionmaker[Session], owner_id: int
) -> None:
    scan_id = _queue_zip(settings, factory, owner_id, ("proj/a.py", "first\nsecond\n"))
    assert runner.process_next(settings, factory) is True

    scan = _scan(factory, scan_id)
    assert scan.status == "done" and scan.error is None
    assert scan.exit_code == 1 and scan.gate_passed is False
    summary = json.loads(scan.summary_json or "{}")
    assert summary["finding_count"] == 1 and summary["tools"][0]["tool"] == "good"
    with factory() as session:
        total, rows = repo.list_findings(session, scan_id)
    assert total == 1
    finding = json.loads(rows[0])
    assert finding["rule_id"] == "R1" and finding["snippet"]["lines"] == ["first", "second"]

    report = json.loads((settings.reports_dir / scan_id / "report.json").read_text())
    assert report["target"] == "project.zip"  # the server-side path is not exposed
    assert str(settings.data_dir) not in json.dumps(report)
    for name in ("report.md", "report.html"):
        assert (settings.reports_dir / scan_id / name).is_file()
    assert not (settings.work_dir / scan_id).exists()
    assert not (settings.uploads_dir / f"{scan_id}.zip").exists()


def test_malicious_zip_fails_safely_and_is_deleted(
    settings: Settings, factory: sessionmaker[Session], owner_id: int
) -> None:
    scan_id = _queue_zip(settings, factory, owner_id, ("../../evil.txt", "pwned"))
    runner.process_next(settings, factory)
    scan = _scan(factory, scan_id)
    assert scan.status == "failed" and "traversal" in (scan.error or "")
    assert not (settings.data_dir.parent / "evil.txt").exists()
    assert not (settings.uploads_dir / f"{scan_id}.zip").exists()
    assert not (settings.work_dir / scan_id).exists()


def test_git_scan_to_a_private_host_is_refused(
    settings: Settings, factory: sessionmaker[Session], owner_id: int
) -> None:
    with session_scope(factory) as session:
        scan = repo.create_scan(
            session, owner_id, repo.NewScan("git", "https://127.0.0.1/a/b", "main")
        )
    runner.process_next(settings, factory)
    failed = _scan(factory, scan.id)
    assert failed.status == "failed" and "public" in (failed.error or "")


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (SandboxResult(None, True, ""), "time limit"),
        (SandboxResult(125, False, "docker: boom"), "sandbox failed"),
        (SandboxResult(137, False, ""), "sandbox failed"),
    ],
)
def test_sandbox_failures_are_reported(
    settings: Settings,
    factory: sessionmaker[Session],
    owner_id: int,
    monkeypatch: pytest.MonkeyPatch,
    result: SandboxResult,
    message: str,
) -> None:
    monkeypatch.setattr(runner, "run_in_sandbox", lambda *args, **kwargs: result)
    scan_id = _queue_zip(settings, factory, owner_id, ("a.py", "x"))
    runner.process_next(settings, factory)
    scan = _scan(factory, scan_id)
    assert scan.status == "failed" and message in (scan.error or "")
    assert "boom" not in (scan.error or "")


def test_unexpected_errors_do_not_leak_details(
    settings: Settings,
    factory: sessionmaker[Session],
    owner_id: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(*args: object, **kwargs: object) -> SandboxResult:
        raise RuntimeError("/srv/secret/path leaked")

    monkeypatch.setattr(runner, "run_in_sandbox", explode)
    scan_id = _queue_zip(settings, factory, owner_id, ("a.py", "x"))
    runner.process_next(settings, factory)
    scan = _scan(factory, scan_id)
    assert scan.error == "internal error while scanning"
    assert not (settings.work_dir / scan_id).exists()


def test_missing_report_is_a_failure(
    settings: Settings,
    factory: sessionmaker[Session],
    owner_id: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        runner, "run_in_sandbox", lambda *args, **kwargs: SandboxResult(0, False, "")
    )
    scan_id = _queue_zip(settings, factory, owner_id, ("a.py", "x"))
    runner.process_next(settings, factory)
    assert "usable report" in (_scan(factory, scan_id).error or "")


def test_worker_drains_the_queue(
    settings: Settings, factory: sessionmaker[Session], owner_id: int
) -> None:
    ids = [
        _queue_zip(settings, factory, owner_id, ("a.py", "1")),
        _queue_zip(settings, factory, owner_id, ("b.py", "2")),
    ]
    assert runner.run_worker(settings, factory, once=True) == 2
    assert {_scan(factory, i).status for i in ids} == {"done"}
    assert runner.run_worker(settings, factory, once=True) == 0


def test_worker_stops_when_asked(settings: Settings, factory: sessionmaker[Session]) -> None:
    assert runner.run_worker(settings, factory, should_stop=lambda: True) == 0


def test_docker_command_is_locked_down(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path, sandbox_network="none", sandbox_memory="2g", sandbox_cpus="1"
    )
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir()
    out.mkdir()
    command = docker_command(settings, "abc123", SandboxDirs(src, out))
    pairs = list(zip(command, command[1:], strict=False))
    assert command[:3] == ["docker", "run", "--rm"]
    assert "--read-only" in command
    assert ("--cap-drop", "ALL") in pairs
    assert ("--security-opt", "no-new-privileges") in pairs
    assert ("--user", "10001:10001") in pairs
    assert ("--network", "none") in pairs
    assert ("--memory", "2g") in pairs and ("--memory-swap", "2g") in pairs
    assert ("--cpus", "1") in pairs and ("--pids-limit", "512") in pairs
    assert ("--name", "scanner-abc123") in pairs
    assert f"type=bind,source={src.resolve()},target=/scan,readonly" in command
    assert f"type=bind,source={out.resolve()},target=/out" in command
    assert "type=volume,source=scanner-cache,target=/cache" in command
    assert command[-9:] == [
        "code-scanner-worker", "scan", "/scan", "--format", "json", "--output", "/out/report.json",
        "--progress", "/out/progress.json",
    ]  # fmt: skip
    assert not any("docker.sock" in part for part in command)


def test_docker_command_stages_the_source_on_a_tmpfs(tmp_path: Path) -> None:
    command = docker_command(Settings(data_dir=tmp_path), "abc", SandboxDirs(tmp_path, tmp_path))
    assert any(part.startswith("/work:rw,nosuid") for part in command)
    assert "SCANNER_STAGE_DIR=/work" in command


def test_docker_command_without_a_cache_volume_uses_tmpfs(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, sandbox_cache_volume="")
    command = docker_command(settings, "abc", SandboxDirs(tmp_path, tmp_path))
    assert not any("type=volume" in part for part in command)
    assert any(part.startswith("/cache:rw") for part in command)


def test_docker_command_rejects_paths_that_could_inject_mount_options(tmp_path: Path) -> None:
    bad = tmp_path / "a,readonly=false"
    bad.mkdir()
    with pytest.raises(Exception, match="commas"):
        docker_command(Settings(data_dir=tmp_path), "abc", SandboxDirs(bad, tmp_path))


def test_settings_from_env(tmp_path: Path) -> None:
    settings = Settings.from_env(
        {
            "SCANNER_DATA_DIR": str(tmp_path),
            "SCANNER_MAX_UPLOAD_MB": "7",
            "SCANNER_SANDBOX": "local",
        }
    )
    assert settings.max_upload_bytes == 7 * 1024 * 1024 and settings.sandbox_mode == "local"
    assert settings.db_url.startswith("sqlite:///")
    for env in (
        {"SCANNER_MAX_UPLOAD_MB": "0"},
        {"SCANNER_MAX_UPLOAD_MB": "x"},
        {"SCANNER_SANDBOX": "vm"},
    ):
        with pytest.raises(ValueError):
            Settings.from_env(env)
