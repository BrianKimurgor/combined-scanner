import logging
import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("scanner.access")


class AccessLogMiddleware:
    """One line per request; the query string and headers (which can hold keys) are left out."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        started = time.perf_counter()
        status = 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            if scope["path"] not in {"/healthz", "/readyz", "/metrics"}:
                logger.info(
                    "%s %s %d",
                    scope["method"],
                    scope["path"],
                    status,
                    extra={
                        "method": scope["method"],
                        "path": scope["path"],
                        "status": status,
                        "ms": round((time.perf_counter() - started) * 1000, 1),
                    },
                )
