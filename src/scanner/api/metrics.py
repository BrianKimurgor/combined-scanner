import hmac
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import text

from scanner.api.auth import SessionDep
from scanner.db import repo
from scanner.settings import Settings

router = APIRouter()

BUCKETS = (5, 15, 30, 60, 120, 300, 600, 1800)
STATUSES = ("queued", "running", "done", "failed")


def render_metrics(snapshot: repo.MetricsSnapshot, now: datetime) -> str:
    by_status, durations = snapshot.by_status, snapshot.durations
    oldest = snapshot.oldest_queued
    age = (now - oldest).total_seconds() if oldest else 0
    lines = ["# TYPE scanner_scans gauge"]
    lines += [f'scanner_scans{{status="{s}"}} {by_status.get(s, 0)}' for s in STATUSES]
    lines += [
        "# TYPE scanner_scans_gate_failed gauge",
        f"scanner_scans_gate_failed {snapshot.gate_failed}",
        "# TYPE scanner_queue_oldest_age_seconds gauge",
        f"scanner_queue_oldest_age_seconds {age:.0f}",
        "# TYPE scanner_api_keys_active gauge",
        f"scanner_api_keys_active {snapshot.keys_active}",
        "# HELP scanner_scan_duration_seconds Duration of the last 1000 finished scans.",
        "# TYPE scanner_scan_duration_seconds histogram",
    ]
    lines += [
        f'scanner_scan_duration_seconds_bucket{{le="{b}"}} {sum(1 for d in durations if d <= b)}'
        for b in BUCKETS
    ]
    lines += [
        f'scanner_scan_duration_seconds_bucket{{le="+Inf"}} {len(durations)}',
        f"scanner_scan_duration_seconds_sum {sum(durations):.1f}",
        f"scanner_scan_duration_seconds_count {len(durations)}",
    ]
    return "\n".join(lines) + "\n"


@router.get("/metrics", include_in_schema=False)
def metrics(request: Request, session: SessionDep) -> Response:
    """Prometheus metrics, off unless SCANNER_METRICS_TOKEN is set."""
    settings: Settings = request.app.state.settings
    if not settings.metrics_token:
        raise HTTPException(404, "not found")
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.strip(), settings.metrics_token):
        raise HTTPException(401, "bad metrics token", headers={"WWW-Authenticate": "Bearer"})
    body = render_metrics(repo.metrics_snapshot(session), datetime.now(UTC))
    return Response(body, media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/readyz", include_in_schema=False)
def ready(session: SessionDep) -> dict[str, str]:
    session.execute(text("SELECT 1"))
    return {"status": "ready"}
