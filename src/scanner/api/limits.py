import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from scanner.api.asgi import HttpMiddleware

MIB = 1024 * 1024
MULTIPART_OVERHEAD = MIB  # form boundaries and headers around the uploaded file


class _TooLarge(Exception):
    pass


class SecurityHeadersMiddleware(HttpMiddleware):
    HEADERS = (
        (b"x-content-type-options", b"nosniff"),
        (b"referrer-policy", b"no-referrer"),
        (b"x-frame-options", b"DENY"),
        (b"cache-control", b"no-store"),
        (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'"),
    )
    DOC_PATHS = ("/docs", "/redoc", "/openapi.json")  # interactive docs need their own scripts

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        skip_csp = scope["path"].startswith(self.DOC_PATHS)

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                present = {name.lower() for name, _ in message["headers"]}
                message["headers"] = [
                    *message["headers"],
                    *(
                        h
                        for h in self.HEADERS
                        if h[0] not in present and not (skip_csp and h[0].startswith(b"content-s"))
                    ),
                ]
            await send(message)

        await self.app(scope, receive, send_with_headers)


class BodySizeLimitMiddleware(HttpMiddleware):
    """Reject oversized request bodies, including chunked ones that send no Content-Length."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await self._reject(send)
            return
        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _TooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = json.dumps({"detail": "request body is too large"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
