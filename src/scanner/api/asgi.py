from starlette.types import ASGIApp, Receive, Scope, Send


class HttpMiddleware:
    """Base for ASGI middleware that acts on HTTP requests and passes everything else through."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        await self.handle(scope, receive, send)

    async def handle(self, scope: Scope, receive: Receive, send: Send) -> None:
        raise NotImplementedError
