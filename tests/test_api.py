import io
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from fakes import GoodPlugin
from scanner.api.app import create_app
from scanner.db import repo
from scanner.db.session import session_scope
from scanner.settings import Settings
from scanner.worker import runner


class FakeSemgrep(GoodPlugin):
    name = "semgrep"


@dataclass
class Env:
    client: TestClient
    settings: Settings
    factory: sessionmaker[Session]
    key: str

    @property
    def headers(self) -> dict[str, str]:
        return {"X-API-Key": self.key}

    def new_key(self, name: str) -> str:
        with session_scope(self.factory) as session:
            return repo.create_api_key(session, name)

    def upload(
        self, data: bytes | None = None, name: str = "proj.zip", key: str | None = None
    ) -> Any:
        return self.client.post(
            "/scans",
            files={
                "file": (
                    name,
                    data if data is not None else make_zip(("proj/a.py", "first\nsecond\n")),
                )
            },
            headers={"X-API-Key": key or self.key},
        )

    def run_worker(self) -> None:
        runner.run_worker(self.settings, self.factory, once=True)


def make_zip(*entries: tuple[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        for name, text in entries:
            zf.writestr(name, text)
    return buffer.getvalue()


def build_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides: Any) -> Env:
    monkeypatch.setattr("scanner.worker.sandbox.build_plugins", lambda names: [FakeSemgrep()])
    fields: dict[str, Any] = {"data_dir": tmp_path / "data", "sandbox_mode": "local"}
    settings = Settings(**{**fields, **overrides})
    app = create_app(settings)
    env = Env(TestClient(app), settings, app.state.session_factory, "")
    env.key = env.new_key("owner")
    return env


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    yield build_env(tmp_path, monkeypatch)


def test_health_is_open_but_everything_else_needs_a_key(env: Env) -> None:
    assert env.client.get("/healthz").json() == {"status": "ok"}
    assert env.client.post("/scans").status_code == 401
    assert env.client.get("/scans/" + "0" * 32).status_code == 401
    bad = {"X-API-Key": "cs_wrong"}
    assert env.client.get("/scans/" + "0" * 32, headers=bad).status_code == 401
    assert env.client.get("/scans/" + "0" * 32, headers=bad).headers["www-authenticate"] == "Bearer"


def test_bearer_tokens_work_too(env: Env) -> None:
    response = env.client.get("/scans/" + "0" * 32, headers={"Authorization": f"Bearer {env.key}"})
    assert response.status_code == 404  # authenticated, but no such scan


def test_responses_carry_security_headers(env: Env) -> None:
    headers = env.client.get("/healthz").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"


def test_upload_is_queued(env: Env) -> None:
    response = env.upload()
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    assert len(scan_id) == 32 and response.json()["status"] == "queued"
    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["status"] == "queued" and status["source"] == "proj.zip"
    assert (env.settings.uploads_dir / f"{scan_id}.zip").is_file()


def test_scans_are_isolated_between_keys(env: Env) -> None:
    scan_id = env.upload().json()["scan_id"]
    other = env.new_key("intruder")
    assert env.client.get(f"/scans/{scan_id}", headers={"X-API-Key": other}).status_code == 404
    assert (
        env.client.get(f"/scans/{scan_id}/findings", headers={"X-API-Key": other}).status_code
        == 404
    )
    assert (
        env.client.get(f"/scans/{scan_id}/report", headers={"X-API-Key": other}).status_code == 404
    )


@pytest.mark.parametrize("scan_id", ["short", "G" * 32, "../" * 11 + "etc", "0" * 33])
def test_malformed_scan_ids_are_rejected(env: Env, scan_id: str) -> None:
    assert env.client.get(f"/scans/{scan_id}", headers=env.headers).status_code in (404, 422)
    assert env.client.get(f"/scans/{scan_id}/report", headers=env.headers).status_code in (404, 422)


def test_uploads_must_be_zip_archives(env: Env) -> None:
    assert env.upload(b"just some text").status_code == 400
    assert env.upload(b"").status_code == 400
    assert list(env.settings.uploads_dir.iterdir()) == []  # nothing left behind


def test_missing_file_field(env: Env) -> None:
    response = env.client.post(
        "/scans", data={"other": "x"}, files={"nofile": ("a.txt", b"x")}, headers=env.headers
    )
    assert response.status_code == 400


def test_unsupported_content_type(env: Env) -> None:
    response = env.client.post(
        "/scans", content=b"x", headers={**env.headers, "content-type": "text/plain"}
    )
    assert response.status_code == 415


def test_oversized_uploads_are_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = build_env(tmp_path, monkeypatch, max_upload_bytes=1000)
    over_limit = b"PK\x03\x04" + b"0" * 5000
    assert env.upload(over_limit).status_code == 413  # caught while streaming to disk
    assert list(env.settings.uploads_dir.iterdir()) == []
    huge = b"PK\x03\x04" + b"0" * (2 * 1024 * 1024)
    assert env.upload(huge).status_code == 413  # caught by the body-size middleware


def test_chunked_bodies_without_content_length_are_limited(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = build_env(tmp_path, monkeypatch, max_upload_bytes=1000)

    def body() -> Iterator[bytes]:
        for _ in range(4):
            yield b"x" * (512 * 1024)

    response = env.client.post(
        "/scans",
        content=body(),
        headers={**env.headers, "content-type": "multipart/form-data; boundary=x"},
    )
    assert response.status_code == 413


def test_git_requests_are_validated_before_queueing(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("scanner.ingest.git_checkout._resolve", lambda host: ["93.184.216.34"])
    ok = env.client.post(
        "/scans", json={"git_url": "https://github.com/a/b", "ref": "main"}, headers=env.headers
    )
    assert ok.status_code == 202
    status = env.client.get(f"/scans/{ok.json()['scan_id']}", headers=env.headers).json()
    assert status["source_type"] == "git" and status["source"] == "https://github.com/a/b@main"

    for payload in (
        {"git_url": "http://github.com/a/b"},
        {"git_url": "https://user:pw@github.com/a/b"},
        {"git_url": "https://github.com/a/b", "ref": "--upload-pack=evil"},
    ):
        assert env.client.post("/scans", json=payload, headers=env.headers).status_code == 400
    assert env.client.post("/scans", json={"nope": 1}, headers=env.headers).status_code == 422
    assert (
        env.client.post(
            "/scans", content=b"{bad", headers={**env.headers, "content-type": "application/json"}
        ).status_code
        == 422
    )


def test_git_requests_to_internal_hosts_are_refused(env: Env) -> None:
    for url in ("https://127.0.0.1/a/b", "https://169.254.169.254/latest", "https://[::1]/x"):
        response = env.client.post("/scans", json={"git_url": url}, headers=env.headers)
        assert response.status_code == 400 and "public" in response.json()["detail"]


def test_per_key_rate_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = build_env(tmp_path, monkeypatch, max_scans_per_hour=2)
    assert env.upload().status_code == 202
    assert env.upload().status_code == 202
    limited = env.upload()
    assert limited.status_code == 429 and limited.headers["retry-after"] == "3600"
    assert env.upload(key=env.new_key("other")).status_code == 202  # limits are per key


def test_full_queue_rejects_new_scans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = build_env(tmp_path, monkeypatch, max_queued_scans=1)
    assert env.upload().status_code == 202
    assert env.upload().status_code == 503


def test_results_are_not_available_until_the_scan_is_done(env: Env) -> None:
    scan_id = env.upload().json()["scan_id"]
    assert env.client.get(f"/scans/{scan_id}/findings", headers=env.headers).status_code == 409
    assert env.client.get(f"/scans/{scan_id}/report", headers=env.headers).status_code == 409


def test_end_to_end_scan(env: Env) -> None:
    scan_id = env.upload().json()["scan_id"]
    env.run_worker()

    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["status"] == "done" and status["exit_code"] == 1
    assert status["gate"]["passed"] is False
    assert status["score"]["percent"] == 95.0
    assert status["finding_count"] == 1 and status["by_severity"] == {"high": 1}
    assert [t["tool"] for t in status["tools"]] == ["semgrep"]
    assert status["finished_at"] is not None

    page = env.client.get(f"/scans/{scan_id}/findings", headers=env.headers).json()
    assert page["total"] == 1
    finding = page["items"][0]
    assert finding["rule_id"] == "R1" and finding["file"] == "a.py"
    assert finding["snippet"]["lines"] == ["first", "second"]


def test_finding_filters_and_pagination(env: Env) -> None:
    scan_id = env.upload().json()["scan_id"]
    env.run_worker()
    url = f"/scans/{scan_id}/findings"

    def total(**params: Any) -> int:
        response = env.client.get(url, params=params, headers=env.headers)
        assert response.status_code == 200
        return int(response.json()["total"])

    assert total(severity="high") == 1 and total(severity="low") == 0
    assert total(category="code") == 1 and total(category="secret") == 0
    assert total(tool="semgrep") == 1 and total(tool="osv") == 0
    assert total(severity="high", category="code", tool="semgrep") == 1
    assert (
        env.client.get(url, params={"limit": 1, "offset": 1}, headers=env.headers).json()["items"]
        == []
    )
    for bad in (
        {"severity": "urgent"},
        {"category": "nope"},
        {"tool": "x%"},
        {"limit": 0},
        {"limit": 501},
        {"offset": -1},
    ):
        assert env.client.get(url, params=bad, headers=env.headers).status_code == 422


def test_reports_in_every_format(env: Env) -> None:
    scan_id = env.upload().json()["scan_id"]
    env.run_worker()
    base = f"/scans/{scan_id}/report"

    as_json = env.client.get(base, headers=env.headers)
    assert as_json.headers["content-type"].startswith("application/json")
    assert as_json.json()["target"] == "proj.zip"
    assert str(env.settings.data_dir) not in as_json.text

    markdown = env.client.get(base, params={"format": "md"}, headers=env.headers)
    assert markdown.headers["content-type"].startswith("text/markdown")
    assert markdown.text.startswith("# Code Scan Report")

    page = env.client.get(base, params={"format": "html"}, headers=env.headers)
    assert page.headers["content-type"].startswith("text/html")
    assert page.text.startswith("<!doctype html>") and "Content-Security-Policy" in page.text
    assert page.headers["x-content-type-options"] == "nosniff"

    assert env.client.get(base, params={"format": "pdf"}, headers=env.headers).status_code == 422


def test_failed_scans_report_the_reason(env: Env) -> None:
    scan_id = env.upload(make_zip(("../../evil.txt", "x"))).json()["scan_id"]
    env.run_worker()
    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["status"] == "failed" and "traversal" in status["error"]
    assert env.client.get(f"/scans/{scan_id}/report", headers=env.headers).status_code == 409
