from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from scanner.api.accesslog import AccessLogMiddleware
from scanner.api.history import router as history_router
from scanner.api.limits import (
    MULTIPART_OVERHEAD,
    BodySizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from scanner.api.metrics import router as metrics_router
from scanner.api.policy import router as policy_router
from scanner.api.routes import router
from scanner.api.ui import STATIC_DIR, LoginThrottle
from scanner.api.ui import router as ui_router
from scanner.db.session import init_db, make_engine, make_session_factory
from scanner.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    engine = make_engine(settings)
    init_db(engine)
    for directory in (settings.uploads_dir, settings.work_dir, settings.reports_dir):
        directory.mkdir(parents=True, exist_ok=True)

    app = FastAPI(title="Code Scanner", version="0.1.0")
    app.state.settings = settings
    app.state.session_factory = make_session_factory(engine)
    app.state.login_throttle = LoginThrottle()
    app.include_router(router)
    app.include_router(history_router)
    app.include_router(policy_router)
    app.include_router(ui_router)
    app.include_router(metrics_router)
    app.mount("/ui/static", StaticFiles(directory=STATIC_DIR), name="ui-static")

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(
        BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes + MULTIPART_OVERHEAD
    )
    return app
