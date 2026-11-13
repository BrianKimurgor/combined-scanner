from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path

import pytest

from scanner.api.ui import MAX_FAILED_LOGINS
from test_api import Env, build_env, make_zip


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Env]:
    yield build_env(tmp_path, monkeypatch, cookie_secure=False)


UI = {"X-Requested-With": "scanner-ui"}


def finished_scan(env: Env, name: str = "proj.zip", **form: str) -> str:
    response = env.client.post(
        "/scans",
        files={"file": (name, make_zip(("proj/a.py", "first\nsecond\n")))},
        data=form,
        headers=env.headers,
    )
    assert response.status_code == 202, response.text
    env.run_worker()
    return str(response.json()["scan_id"])


def first_fingerprint(env: Env, scan_id: str) -> str:
    items = env.client.get(f"/scans/{scan_id}/findings", headers=env.headers).json()["items"]
    return str(items[0]["fingerprint"])


def suppress(env: Env, scan_id: str, fingerprint: str, days: int = 30) -> dict[str, object]:
    response = env.client.post(
        "/suppressions",
        json={
            "scan_id": scan_id,
            "fingerprint": fingerprint,
            "reason": "accepted risk",
            "expires": (date.today() + timedelta(days=days)).isoformat(),
        },
        headers=env.headers,
    )
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def login(env: Env) -> None:
    response = env.client.post("/ui/session", json={"api_key": env.key}, headers=UI)
    assert response.status_code == 200, response.text


# ----------------------------------------------------------------- browser sessions


def test_login_sets_a_http_only_cookie_that_authenticates_reads(env: Env) -> None:
    env.client.cookies.clear()
    response = env.client.post("/ui/session", json={"api_key": env.key}, headers=UI)
    cookie = response.headers["set-cookie"].lower()
    assert response.json() == {"name": "owner"}
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert env.client.get("/scans").status_code == 200
    assert env.client.get("/ui/session").json() == {"name": "owner"}


def test_login_rejects_a_bad_key_and_requires_the_ui_header(env: Env) -> None:
    bad = env.client.post("/ui/session", json={"api_key": "cs_wrong"}, headers=UI)
    assert bad.status_code == 401
    assert "set-cookie" not in bad.headers
    no_header = env.client.post("/ui/session", json={"api_key": env.key})
    assert no_header.status_code == 403
    foreign = env.client.post(
        "/ui/session", json={"api_key": env.key}, headers={**UI, "Origin": "http://evil.example"}
    )
    assert foreign.status_code == 403


def test_cookie_requests_that_change_things_need_the_ui_header_and_same_origin(env: Env) -> None:
    login(env)
    body = {"name": "base"}
    scan_id = finished_scan(env)
    url = f"/scans/{scan_id}/baseline"
    assert env.client.post(url, json=body).status_code == 403
    cross = env.client.post(url, json=body, headers={**UI, "Origin": "http://evil.example"})
    assert cross.status_code == 403
    same = env.client.post(url, json=body, headers={**UI, "Origin": "http://testserver"})
    assert same.status_code == 201


def test_logout_ends_the_session(env: Env) -> None:
    login(env)
    assert env.client.delete("/ui/session", headers=UI).status_code == 204
    env.client.cookies.clear()
    assert env.client.get("/scans").status_code == 401


def test_a_revoked_session_token_stops_working(env: Env) -> None:
    login(env)
    token = env.client.cookies.get("scanner_session")
    assert token
    env.client.delete("/ui/session", headers=UI)
    env.client.cookies.set("scanner_session", token)
    assert env.client.get("/scans").status_code == 401


def test_repeated_failed_logins_are_throttled(env: Env) -> None:
    for _ in range(MAX_FAILED_LOGINS):
        assert (
            env.client.post("/ui/session", json={"api_key": "cs_bad"}, headers=UI).status_code
            == 401
        )
    blocked = env.client.post("/ui/session", json={"api_key": env.key}, headers=UI)
    assert blocked.status_code == 429


# ----------------------------------------------------------------- pages


def test_ui_page_has_a_strict_content_security_policy(env: Env) -> None:
    response = env.client.get("/ui/")
    policy = response.headers["content-security-policy"]
    assert response.status_code == 200
    assert "script-src 'self'" in policy and "unsafe-inline" not in policy
    assert "frame-ancestors 'none'" in policy
    assert "/ui/static/app.js" in response.text
    assert "<script>" not in response.text and "style=" not in response.text


def test_static_assets_are_served(env: Env) -> None:
    assert env.client.get("/ui/static/app.js").status_code == 200
    assert env.client.get("/ui/static/app.css").status_code == 200
    assert env.client.get("/ui/static/..%2f..%2fsettings.py").status_code == 404


def test_api_responses_default_to_a_locked_down_policy(env: Env) -> None:
    response = env.client.get("/healthz")
    assert response.headers["content-security-policy"].startswith("default-src 'none'")


def test_html_report_is_sandboxed_and_frameable_only_by_this_site(env: Env) -> None:
    scan_id = finished_scan(env)
    html = env.client.get(f"/scans/{scan_id}/report?format=html", headers=env.headers)
    assert html.headers["content-security-policy"].startswith("sandbox allow-scripts")
    assert html.headers["x-frame-options"] == "SAMEORIGIN"
    markdown = env.client.get(f"/scans/{scan_id}/report?format=md", headers=env.headers)
    assert "attachment" in markdown.headers["content-disposition"]


# ----------------------------------------------------------------- history and trends


def test_history_sources_and_trends(env: Env) -> None:
    first = finished_scan(env)
    second = finished_scan(env, name="other.zip")
    page = env.client.get("/scans", headers=env.headers).json()
    assert page["total"] == 2
    assert [s["id"] for s in page["items"]] == [second, first]
    only_other = env.client.get("/scans?source=other.zip", headers=env.headers).json()
    assert [s["id"] for s in only_other["items"]] == [second]
    assert env.client.get("/scans?status=bogus", headers=env.headers).status_code == 422
    sources = env.client.get("/sources", headers=env.headers).json()
    assert {s["source"] for s in sources} == {"proj.zip", "other.zip"}
    trend = env.client.get("/trends?source=proj.zip", headers=env.headers).json()
    assert [p["scan_id"] for p in trend["points"]] == [first]
    assert trend["points"][0]["counted"] == 1
    assert env.client.get("/trends", headers=env.headers).status_code == 422


def test_history_is_private_to_the_owner(env: Env) -> None:
    finished_scan(env)
    other = env.new_key("other")
    assert env.client.get("/scans", headers={"X-API-Key": other}).json()["total"] == 0
    assert env.client.get("/sources", headers={"X-API-Key": other}).json() == []


# ----------------------------------------------------------------- suppressions


def test_suppressing_a_finding_stops_it_counting_and_persists_for_later_scans(env: Env) -> None:
    scan_id = finished_scan(env)
    assert (
        env.client.get(f"/scans/{scan_id}", headers=env.headers).json()["gate"]["passed"] is False
    )
    fingerprint = first_fingerprint(env, scan_id)
    suppress(env, scan_id, fingerprint)

    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["gate"]["passed"] is True
    assert (status["counted_count"], status["suppressed_count"]) == (0, 1)
    hidden = env.client.get(f"/scans/{scan_id}/findings?suppressed=false", headers=env.headers)
    shown = env.client.get(f"/scans/{scan_id}/findings?suppressed=true", headers=env.headers)
    assert hidden.json()["total"] == 0
    item = shown.json()["items"][0]
    assert item["suppressed"]["reason"] == "accepted risk"

    later = finished_scan(env)
    assert env.client.get(f"/scans/{later}", headers=env.headers).json()["gate"]["passed"] is True


def test_removing_a_suppression_brings_the_finding_back(env: Env) -> None:
    scan_id = finished_scan(env)
    created = suppress(env, scan_id, first_fingerprint(env, scan_id))
    listed = env.client.get("/suppressions", headers=env.headers).json()
    assert [s["id"] for s in listed] == [created["id"]]
    assert (
        env.client.delete(f"/suppressions/{created['id']}", headers=env.headers).status_code == 204
    )
    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert (status["counted_count"], status["suppressed_count"]) == (1, 0)
    assert (
        env.client.delete(f"/suppressions/{created['id']}", headers=env.headers).status_code == 404
    )


def test_suppression_input_is_validated(env: Env) -> None:
    scan_id = finished_scan(env)
    fingerprint = first_fingerprint(env, scan_id)
    payload = {
        "scan_id": scan_id,
        "fingerprint": fingerprint,
        "reason": "ok",
        "expires": (date.today() + timedelta(days=5)).isoformat(),
    }

    def post(**changes: str) -> int:
        return env.client.post(
            "/suppressions", json={**payload, **changes}, headers=env.headers
        ).status_code

    assert post(expires=date.today().isoformat()) == 422
    assert post(expires=(date.today() + timedelta(days=400)).isoformat()) == 422
    assert post(reason="") == 422
    assert post(reason="   ") == 422
    assert post(fingerprint="zz") == 422
    assert post(fingerprint="0" * 16) == 404
    assert post(scan_id="0" * 32) == 404


def test_one_owner_cannot_suppress_or_remove_anothers_findings(env: Env) -> None:
    scan_id = finished_scan(env)
    fingerprint = first_fingerprint(env, scan_id)
    created = suppress(env, scan_id, fingerprint)
    other = {"X-API-Key": env.new_key("other")}
    body = {
        "scan_id": scan_id,
        "fingerprint": fingerprint,
        "reason": "mine now",
        "expires": (date.today() + timedelta(days=5)).isoformat(),
    }
    assert env.client.post("/suppressions", json=body, headers=other).status_code == 404
    assert env.client.delete(f"/suppressions/{created['id']}", headers=other).status_code == 404
    assert env.client.get("/suppressions", headers=other).json() == []


# ----------------------------------------------------------------- baselines


def test_a_baseline_accepts_existing_findings_for_later_scans(env: Env) -> None:
    scan_id = finished_scan(env)
    made = env.client.post(
        f"/scans/{scan_id}/baseline", json={"name": "release-1"}, headers=env.headers
    )
    assert made.status_code == 201
    assert made.json()["size"] == 1
    duplicate = env.client.post(
        f"/scans/{scan_id}/baseline", json={"name": "release-1"}, headers=env.headers
    )
    assert duplicate.status_code == 409

    later = finished_scan(env, baseline_id=str(made.json()["id"]))
    status = env.client.get(f"/scans/{later}", headers=env.headers).json()
    assert status["baseline_id"] == made.json()["id"]
    assert status["baseline"]["existing_count"] == 1
    assert (status["counted_count"], status["gate"]["passed"]) == (0, True)
    existing = env.client.get(f"/scans/{later}/findings?new=false", headers=env.headers)
    assert existing.json()["total"] == 1


def test_baselines_can_be_listed_and_deleted_and_used_in_json_requests(env: Env) -> None:
    scan_id = finished_scan(env)
    made = env.client.post(
        f"/scans/{scan_id}/baseline", json={"name": "b"}, headers=env.headers
    ).json()
    assert [b["name"] for b in env.client.get("/baselines", headers=env.headers).json()] == ["b"]
    unknown = env.client.post(
        "/scans",
        json={"git_url": "https://example.com/r.git", "baseline_id": 999},
        headers=env.headers,
    )
    assert unknown.status_code == 400
    assert env.client.delete(f"/baselines/{made['id']}", headers=env.headers).status_code == 204
    assert env.client.delete(f"/baselines/{made['id']}", headers=env.headers).status_code == 404


def test_baselines_are_private_and_need_a_finished_scan(env: Env) -> None:
    scan_id = finished_scan(env)
    other = {"X-API-Key": env.new_key("other")}
    assert (
        env.client.post(f"/scans/{scan_id}/baseline", json={"name": "x"}, headers=other).status_code
        == 404
    )
    made = env.client.post(
        f"/scans/{scan_id}/baseline", json={"name": "mine"}, headers=env.headers
    ).json()
    assert env.client.get("/baselines", headers=other).json() == []
    response = env.client.post(
        "/scans",
        files={"file": ("p.zip", make_zip(("a.py", "x")))},
        data={"baseline_id": str(made["id"] + 100)},
        headers=env.headers,
    )
    assert response.status_code == 400
    bad = env.client.post(
        "/scans",
        files={"file": ("p.zip", make_zip(("a.py", "x")))},
        data={"baseline_id": "abc"},
        headers=env.headers,
    )
    assert bad.status_code == 400
