import time
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session, sessionmaker

from scanner.api.auth import SESSION_COOKIE, OwnerDep, require_same_origin
from scanner.api.schemas import LoginRequest, SessionInfo
from scanner.db import repo
from scanner.db.session import session_scope
from scanner.settings import Settings

router = APIRouter()

STATIC_DIR = Path(__file__).parent / "static"
# Everything on the page comes from this site; nothing inline, nothing from elsewhere.
PAGE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-src 'self'; form-action 'none'; base-uri 'none'; "
    "frame-ancestors 'none'"
)
MAX_FAILED_LOGINS = 10
LOGIN_WINDOW_SECONDS = 300


class LoginThrottle:
    """Slow down guessing of API keys through the login form."""

    def __init__(self) -> None:
        self._failures: dict[str, list[float]] = {}

    def _recent(self, client: str) -> list[float]:
        cutoff = time.monotonic() - LOGIN_WINDOW_SECONDS
        recent = [t for t in self._failures.get(client, []) if t > cutoff]
        if recent:
            self._failures[client] = recent
        else:
            self._failures.pop(client, None)
        return recent

    def blocked(self, client: str) -> bool:
        return len(self._recent(client)) >= MAX_FAILED_LOGINS

    def record_failure(self, client: str) -> None:
        self._failures[client] = [*self._recent(client), time.monotonic()]


@router.get("/ui/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(
        STATIC_DIR / "index.html",
        media_type="text/html; charset=utf-8",
        headers={"Content-Security-Policy": PAGE_CSP},
    )


def _login(factory: sessionmaker[Session], settings: Settings, key: str) -> tuple[str, str] | None:
    with session_scope(factory) as session:
        owner = repo.authenticate(session, key)
        if owner is None:
            return None
        lifetime = timedelta(hours=settings.session_hours)
        return owner.name, repo.create_ui_session(session, owner.id, lifetime)


@router.post("/ui/session", response_model=SessionInfo)
async def login(request: Request, body: LoginRequest, response: Response) -> SessionInfo:
    """Trade an API key for a browser session cookie (HttpOnly, so page scripts cannot read it)."""
    require_same_origin(request)
    client = request.client.host if request.client else "unknown"
    throttle: LoginThrottle = request.app.state.login_throttle
    if throttle.blocked(client):
        raise HTTPException(
            429, "too many failed logins; wait a few minutes", headers={"Retry-After": "300"}
        )
    settings: Settings = request.app.state.settings
    factory: sessionmaker[Session] = request.app.state.session_factory
    result = await run_in_threadpool(_login, factory, settings, body.api_key)
    if result is None:
        throttle.record_failure(client)
        raise HTTPException(401, "invalid API key")
    name, token = result
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_hours * 3600,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )
    return SessionInfo(name=name)


@router.get("/ui/session", response_model=SessionInfo)
def whoami(owner: OwnerDep) -> SessionInfo:
    return SessionInfo(name=owner.name)


@router.delete("/ui/session", status_code=204)
def logout(request: Request, owner: OwnerDep) -> Response:
    response = Response(status_code=204)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        factory: sessionmaker[Session] = request.app.state.session_factory
        with session_scope(factory) as session:
            repo.delete_ui_session(session, token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
