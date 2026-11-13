import logging
import time

from starlette.types import Message, Receive, Scope, Send

from scanner.api.asgi import HttpMiddleware

logger = logging.getLogger("scanner.access")


class AccessLogMiddleware(HttpMiddleware):
    """One line per request; the query string and headers (which can hold keys) are left out."""

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
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
