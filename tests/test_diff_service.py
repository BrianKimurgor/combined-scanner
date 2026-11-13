from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import inspect, text

from fakes import VulnGrepPlugin
from scanner.db import repo
from scanner.db.session import init_db, make_engine, make_session_factory, session_scope
from scanner.settings import Settings
from scanner.worker import runner
from scanner.worker.sandbox import docker_command
from test_api import Env, build_env

URL = "https://github.com/acme/app"


def _fake_checkout(trees: dict[str, dict[str, str]]) -> Any:
    def checkout(url: str, ref: str, dest: Path, *, timeout: int, limits: object = None) -> None:
        dest.mkdir(parents=True)
        for name, content in trees[ref].items():
            (dest / name).write_text(content, encoding="utf-8")

    return checkout


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    environment = build_env(tmp_path, monkeypatch)
    monkeypatch.setattr("scanner.worker.sandbox.build_plugins", lambda names: [VulnGrepPlugin()])
    monkeypatch.setattr(
        runner,
        "git_checkout",
        _fake_checkout(
            {
                "main": {"a.py": "VULN old\n"},
                "feature": {"a.py": "VULN old\nVULN new\n", "b.py": "fine\n"},
                "clean": {"a.py": "VULN old\n# edit\n"},
            }
        ),
    )
    monkeypatch.setattr("scanner.ingest.git_checkout._resolve", lambda host: ["93.184.216.34"])
    return environment


def _submit(env: Env, **body: str) -> str:
    response = env.client.post("/scans", json={"git_url": URL, **body}, headers=env.headers)
    assert response.status_code == 202, response.text
    return str(response.json()["scan_id"])


def test_diff_scan_through_the_api(env: Env) -> None:
    scan_id = _submit(env, base="main", ref="feature")
    queued = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert queued["base"] == "main" and queued["source"] == f"{URL}@feature"

    env.run_worker()
    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["status"] == "done" and status["exit_code"] == 1
    assert status["gate"]["passed"] is False
    assert status["by_severity"] == {"high": 1}  # only the new finding
    diff = status["diff"]
    assert (diff["new_count"], diff["existing_count"], diff["fixed_count"]) == (1, 1, 0)
    assert diff["base"] == f"{URL}@main" and diff["head"] == f"{URL}@feature"
    assert {c["path"] for c in diff["changed_files"]} == {"a.py", "b.py"}


def test_findings_can_be_filtered_to_the_new_ones(env: Env) -> None:
    scan_id = _submit(env, base="main", ref="feature")
    env.run_worker()
    url = f"/scans/{scan_id}/findings"
    everything = env.client.get(url, headers=env.headers).json()
    assert everything["total"] == 2
    only_new = env.client.get(url, params={"new": "true"}, headers=env.headers).json()
    assert only_new["total"] == 1 and only_new["items"][0]["is_new"] is True
    assert only_new["items"][0]["line_start"] == 2
    old = env.client.get(url, params={"new": "false"}, headers=env.headers).json()
    assert old["total"] == 1 and old["items"][0]["is_new"] is False


def test_a_change_that_adds_nothing_passes(env: Env) -> None:
    scan_id = _submit(env, base="main", ref="clean")
    env.run_worker()
    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["exit_code"] == 0 and status["gate"]["passed"] is True
    assert status["diff"]["new_count"] == 0 and status["by_severity"] == {}


def test_sarif_report_contains_only_new_findings(env: Env) -> None:
    scan_id = _submit(env, base="main", ref="feature")
    env.run_worker()
    response = env.client.get(
        f"/scans/{scan_id}/report", params={"format": "sarif"}, headers=env.headers
    )
    assert response.headers["content-type"].startswith("application/sarif+json")
    (result,) = response.json()["runs"][0]["results"]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    assert str(env.settings.data_dir) not in response.text


def test_markdown_and_html_reports_describe_the_diff(env: Env) -> None:
    scan_id = _submit(env, base="main", ref="feature")
    env.run_worker()
    markdown = env.client.get(
        f"/scans/{scan_id}/report", params={"format": "md"}, headers=env.headers
    ).text
    assert f"Compared: `{URL}@main` to `{URL}@feature`" in markdown
    page = env.client.get(
        f"/scans/{scan_id}/report", params={"format": "html"}, headers=env.headers
    ).text
    assert "new-tag" in page


def test_both_revisions_are_removed_after_the_scan(env: Env) -> None:
    scan_id = _submit(env, base="main", ref="feature")
    env.run_worker()
    assert not (env.settings.work_dir / scan_id).exists()


@pytest.mark.parametrize("base", ["--upload-pack=evil", "a..b", "x y", "-x"])
def test_unsafe_base_refs_are_rejected(env: Env, base: str) -> None:
    response = env.client.post("/scans", json={"git_url": URL, "base": base}, headers=env.headers)
    assert response.status_code == 400


def test_full_scans_are_unaffected(env: Env) -> None:
    scan_id = _submit(env, ref="feature")
    env.run_worker()
    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["diff"] is None and status["base"] is None
    page = env.client.get(f"/scans/{scan_id}/findings", headers=env.headers).json()
    assert page["total"] == 2 and all(item["is_new"] is None for item in page["items"])


def test_docker_command_mounts_the_base_read_only(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path)
    src, out, base = tmp_path / "src", tmp_path / "out", tmp_path / "base"
    for directory in (src, out, base):
        directory.mkdir()
    command = docker_command(settings, "abc", src, out, base)
    assert f"type=bind,source={base.resolve()},target=/base,readonly" in command
    assert command[-2:] == ["--base-path", "/base"]
    assert command[-11:-2] == [
        "code-scanner-worker",
        "scan",
        "/scan",
        "--format",
        "json",
        "--output",
        "/out/report.json",
        "--progress",
        "/out/progress.json",
    ]
    without = docker_command(settings, "abc", src, out)
    assert not any("/base" in part for part in without)


def test_init_db_adds_columns_missing_from_older_databases(tmp_path: Path) -> None:
    engine = make_engine(Settings(data_dir=tmp_path / "data"))
    with engine.begin() as connection:
        for statement in (
            "CREATE TABLE api_keys (id INTEGER PRIMARY KEY, name VARCHAR(100) UNIQUE, "
            "key_hash VARCHAR(64) UNIQUE, created_at DATETIME, revoked BOOLEAN)",
            "CREATE TABLE scans (id VARCHAR(32) PRIMARY KEY, owner_id INTEGER, status VARCHAR(16), "
            "source_type VARCHAR(8), source_ref VARCHAR(2200), git_ref VARCHAR(200), "
            "created_at DATETIME, "
            "started_at DATETIME, finished_at DATETIME, error TEXT, exit_code INTEGER, "
            "gate_passed BOOLEAN, score_percent FLOAT, summary_json TEXT)",
            "CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_id VARCHAR(32), position INTEGER, "
            "severity VARCHAR(16), category VARCHAR(16), sources VARCHAR(200), data TEXT)",
        ):
            connection.execute(text(statement))
    init_db(engine)
    init_db(engine)  # idempotent
    inspector = inspect(engine)
    assert "base_ref" in {c["name"] for c in inspector.get_columns("scans")}
    assert "is_new" in {c["name"] for c in inspector.get_columns("findings")}

    factory = make_session_factory(engine)
    with session_scope(factory) as session:
        key = repo.create_api_key(session, "old-db")
        owner = repo.authenticate(session, key)
        assert owner is not None
        scan = repo.create_scan(session, owner.id, "git", URL, "feature", None, "main")
    with factory() as session:
        loaded = repo.get_scan(session, owner.id, scan.id)
        assert loaded is not None and loaded.base_ref == "main"
