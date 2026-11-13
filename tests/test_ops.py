import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import func, select
from typer.testing import CliRunner

from scanner.api.metrics import render_metrics
from scanner.cli import app
from scanner.db.models import UiSession
from scanner.db.repo import MetricsSnapshot
from scanner.logging_setup import JsonFormatter
from scanner.settings import Settings
from test_api import Env, build_env

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    yield build_env(tmp_path, monkeypatch, metrics_token="s3cret-metrics")  # noqa: S106


@pytest.fixture
def cli_env(tmp_path: Path) -> dict[str, str]:
    return {"SCANNER_DATA_DIR": str(tmp_path / "data"), "SCANNER_SANDBOX": "local"}


# ----------------------------------------------------------------- metrics and health


def test_metrics_are_off_without_a_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plain = build_env(tmp_path, monkeypatch)
    assert plain.client.get("/metrics").status_code == 404


def test_metrics_need_the_token_and_describe_the_queue(env: Env) -> None:
    assert env.client.get("/metrics").status_code == 401
    wrong = env.client.get("/metrics", headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401
    assert (
        env.client.get("/metrics", headers=env.headers).status_code == 401
    )  # API keys do not work

    queued = env.upload()
    assert queued.status_code == 202
    auth = {"Authorization": "Bearer s3cret-metrics"}
    body = env.client.get("/metrics", headers=auth).text
    assert 'scanner_scans{status="queued"} 1' in body
    assert "scanner_api_keys_active 1" in body

    env.run_worker()
    body = env.client.get("/metrics", headers=auth).text
    assert 'scanner_scans{status="done"} 1' in body
    assert "scanner_scans_gate_failed 1" in body
    assert "scanner_scan_duration_seconds_count 1" in body
    assert 'scanner_scan_duration_seconds_bucket{le="+Inf"} 1' in body


def test_metrics_never_include_scan_content_or_owners(env: Env) -> None:
    env.upload(name="secret-project.zip")
    env.run_worker()
    body = env.client.get("/metrics", headers={"Authorization": "Bearer s3cret-metrics"}).text
    assert "secret-project" not in body and "owner" not in body


def test_histogram_buckets_are_cumulative() -> None:
    from datetime import UTC, datetime

    text = render_metrics(
        MetricsSnapshot({}, 0, None, [1.0, 20.0, 700.0], 0),
        datetime.now(UTC),
    )
    assert 'le="5"} 1' in text and 'le="30"} 2' in text and 'le="+Inf"} 3' in text


def test_readiness_checks_the_database(env: Env) -> None:
    assert env.client.get("/readyz").json() == {"status": "ready"}


# ----------------------------------------------------------------- logging


def test_json_logs_are_one_object_per_line_with_structured_fields() -> None:
    record = logging.LogRecord(
        "scanner.worker", logging.INFO, __file__, 1, "scan %s done", ("x",), None
    )
    record.scan_id = "abc"
    record.seconds = 1.5
    entry = json.loads(JsonFormatter().format(record))
    assert entry["message"] == "scan x done" and entry["level"] == "info"
    assert entry["scan_id"] == "abc" and entry["seconds"] == 1.5
    assert "\n" not in JsonFormatter().format(record)


def test_log_format_setting_is_validated() -> None:
    assert Settings.from_env({"SCANNER_LOG_FORMAT": "json"}).log_format == "json"
    with pytest.raises(ValueError, match="SCANNER_LOG_FORMAT"):
        Settings.from_env({"SCANNER_LOG_FORMAT": "xml"})


def test_access_log_omits_the_query_string_and_credentials(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="scanner.access"):
        env.client.get("/scans?source=private-name", headers=env.headers)
    text = " ".join(r.getMessage() + str(r.__dict__) for r in caplog.records)
    assert "GET /scans 200" in text
    assert "private-name" not in text and env.key not in text


def test_a_finished_scan_is_logged_with_its_outcome(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="scanner.worker.runner"):
        env.upload()
        env.run_worker()
    record = next(r for r in caplog.records if getattr(r, "outcome", None))
    assert record.outcome == "done" and record.findings == 1  # type: ignore[attr-defined]


# ----------------------------------------------------------------- key management


def test_keys_can_be_listed_rotated_and_revoked(cli_env: dict[str, str]) -> None:
    key = runner.invoke(app, ["admin", "create-key", "alice"], env=cli_env).stdout.strip()
    listing = runner.invoke(app, ["admin", "list-keys"], env=cli_env)
    assert "alice\tactive\t0 scan(s)" in listing.output and key not in listing.output

    rotated = runner.invoke(app, ["admin", "rotate-key", "alice"], env=cli_env)
    new_key = rotated.stdout.strip()
    assert rotated.exit_code == 0 and new_key.startswith("cs_") and new_key != key

    revoked = runner.invoke(app, ["admin", "revoke-key", "alice"], env=cli_env)
    assert revoked.exit_code == 0
    assert "alice\trevoked" in runner.invoke(app, ["admin", "list-keys"], env=cli_env).output
    again = runner.invoke(app, ["admin", "rotate-key", "alice"], env=cli_env)
    assert again.exit_code == 2 and "revoked" in again.output


def test_unknown_keys_are_reported(cli_env: dict[str, str]) -> None:
    for command in ("revoke-key", "rotate-key"):
        result = runner.invoke(app, ["admin", command, "ghost"], env=cli_env)
        assert result.exit_code == 2 and "no API key named" in result.output


def test_rotation_and_revocation_take_effect_immediately(env: Env) -> None:
    from scanner.db import repo
    from scanner.db.session import session_scope

    assert (
        env.client.post(
            "/ui/session", json={"api_key": env.key}, headers={"X-Requested-With": "scanner-ui"}
        ).status_code
        == 200
    )
    with session_scope(env.factory) as session:
        new_key = repo.rotate_api_key(session, "owner")
    assert env.client.get("/scans", headers=env.headers).status_code == 401
    assert env.client.get("/scans", headers={"X-API-Key": new_key}).status_code == 200
    with session_scope(env.factory) as session:
        assert session.scalar(select(func.count()).select_from(UiSession)) == 0  # logins ended

    with session_scope(env.factory) as session:
        repo.revoke_api_key(session, "owner")
    assert env.client.get("/scans", headers={"X-API-Key": new_key}).status_code == 401
