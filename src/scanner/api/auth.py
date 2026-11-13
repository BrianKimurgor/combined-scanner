from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from scanner.db import repo
from scanner.db.models import ApiKey
from scanner.db.session import session_scope

SESSION_COOKIE = "scanner_session"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "scanner-ui"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def get_session(request: Request) -> Iterator[Session]:
    with session_scope(request.app.state.session_factory) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def _extract_key(request: Request) -> str | None:
    key = request.headers.get("x-api-key")
    if key:
        return key
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def require_same_origin(request: Request) -> None:
    """Cookie logins can be abused by other sites, so changes must come from our own page."""
    origin = request.headers.get("origin")
    expected = f"{request.url.scheme}://{request.headers.get('host', '')}"
    if request.headers.get(CSRF_HEADER) != CSRF_VALUE or (origin and origin != expected):
        raise HTTPException(status_code=403, detail="cross-site request refused")


def current_owner(request: Request, session: SessionDep) -> ApiKey:
    key = _extract_key(request)
    owner = repo.authenticate(session, key) if key else None
    if owner is None and not key:
        token = request.cookies.get(SESSION_COOKIE)
        owner = repo.authenticate_session(session, token) if token else None
        if owner is not None and request.method not in SAFE_METHODS:
            require_same_origin(request)
    if owner is None:
        raise HTTPException(
            status_code=401,
            detail="missing or invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return owner


OwnerDep = Annotated[ApiKey, Depends(current_owner)]
