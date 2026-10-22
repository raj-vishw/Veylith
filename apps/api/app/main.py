import json
import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from .config import get_settings
from .db import SessionLocal
from .routers import auth, cases, graph, intelligence, inventory, org, reports

API_PREFIX = "/api/v1"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname, "logger": record.name, "msg": record.getMessage()}
        for key in ("request_id", "method", "path", "status", "duration_ms", "source", "changed"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # its INFO lines include full URLs with query strings
    logging.getLogger("uvicorn.access").disabled = True  # we log requests ourselves, without query strings or cookies


configure_logging()
log = logging.getLogger("veylith.api")


def create_app(settings=None) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="Veylith API",
        version="1.0.0",
        description="Third-party incident impact intelligence for MSPs and security teams.",
        docs_url=f"{API_PREFIX}/docs" if settings.environment != "production" else None,
        redoc_url=None,
        openapi_url=f"{API_PREFIX}/openapi.json" if settings.environment != "production" else None,
    )


    @app.middleware("http")
    async def request_middleware(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception("unhandled error", extra={"request_id": request_id, "method": request.method, "path": request.url.path})
            response = JSONResponse({"detail": "Internal server error", "request_id": request_id}, status_code=500)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = response.headers.get("Cache-Control", "no-store")
        if get_settings().cookie_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Path only: query strings and bodies may contain sensitive search terms or credentials.
        log.info("request", extra={"request_id": request_id, "method": request.method, "path": request.url.path,
                                   "status": response.status_code, "duration_ms": round((time.perf_counter() - started) * 1000, 1)})
        return response


    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        # Report where the problem is, never echo submitted values back (they may be passwords).
        errors = [{"loc": [str(p) for p in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "Validation failed", "errors": errors})


    @app.get("/health/live")
    @app.get("/health")
    def health():
        return {"status": "ok"}


    @app.get("/health/ready")
    def ready():
        try:
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return {"status": "ready"}


    for module in (auth, org, inventory, graph, intelligence, cases, reports):
        app.include_router(module.router, prefix=API_PREFIX)
    return app


app = create_app()
