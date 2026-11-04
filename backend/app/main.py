"""SENTINEL — FastAPI Application Entry Point.

The autonomous threat intelligence platform API server.
"""

import logging
from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import update

from app.core.config import get_settings
from app.core.database import engine, Base, async_session
from app.api.routes import router, auth_router, ACTIVE_STATUSES
from app.models.models import AnalysisJob, JobStatus
from app.services.file_service import validate_storage_configuration
from app.services.security_service import validate_runtime_security

settings = get_settings()

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("sentinel")


async def recover_interrupted_jobs() -> int:
    """Fail jobs whose background thread died with the previous process.

    In thread mode a restart (deploy, crash, free-tier sleep) kills running
    analyses, which would otherwise sit in an active status forever and count
    against the tenant's active-job limit.
    """
    if settings.USE_CELERY:
        return 0

    from app.worker import INTERRUPTED_MESSAGE

    async with async_session() as session:
        result = await session.execute(
            update(AnalysisJob)
            .where(AnalysisJob.status.in_(ACTIVE_STATUSES))
            .values(status=JobStatus.FAILED.value, error_message=INTERRUPTED_MESSAGE)
        )
        await session.commit()
    return result.rowcount or 0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — create tables on startup."""
    validate_runtime_security(settings)
    validate_storage_configuration()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    recovered = await recover_interrupted_jobs()
    if recovered:
        logger.warning("Marked %d interrupted analysis job(s) as failed", recovered)
    yield
    await engine.dispose()


app = FastAPI(
    title="SENTINEL API",
    description=(
        "The Autonomous Threat Intelligence Platform. "
        "Upload suspicious files, receive AI-powered threat analysis in under 60 seconds."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.docs_enabled else None,
    redoc_url="/redoc" if settings.docs_enabled else None,
    openapi_url="/openapi.json" if settings.docs_enabled else None,
    lifespan=lifespan,
)


# ── Error Handling ───────────────────────────────────────────────

def _field_label(loc) -> str:
    parts = [str(part) for part in loc if part not in ("body", "query", "path")]
    return ".".join(parts).replace("_", " ") or "request"


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Return readable validation errors without echoing submitted values.

    FastAPI's default 422 body includes each rejected input, which would
    reflect passwords back to the client and into any logs that capture it.
    """
    errors = [
        {
            "field": _field_label(err.get("loc", ())),
            "message": str(err.get("msg", "Invalid value")).removeprefix("Value error, "),
        }
        for err in exc.errors()
    ]
    summary = "; ".join(f"{e['field'].capitalize()}: {e['message']}" for e in errors[:3])
    return JSONResponse(
        status_code=422,
        content={"detail": summary or "Invalid request", "errors": errors},
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    """Log unexpected failures with a reference ID and hide internals from clients."""
    reference = getattr(request.state, "request_id", None) or uuid4().hex[:12]
    logger.exception("Unhandled error [%s] %s %s", reference, request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={
            "detail": f"Something went wrong on our side. Reference: {reference}",
            "reference": reference,
        },
        headers={"X-Request-ID": reference},
    )


# ── Request Guards & Security Headers ────────────────────────────

@app.middleware("http")
async def guard_and_secure(request: Request, call_next):
    request.state.request_id = uuid4().hex[:12]

    # Reject oversized bodies before the multipart parser spools them to disk.
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            too_large = int(content_length) > settings.max_request_body_bytes
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
        if too_large:
            return JSONResponse(
                status_code=413,
                content={"detail": f"File exceeds maximum size of {settings.MAX_FILE_SIZE_MB}MB"},
            )

    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
        # API responses are data, never documents; nothing should render or run.
        response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if not settings.DEBUG:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# ── CORS Middleware ──────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Route Registration ──────────────────────────────────────────
app.include_router(router)
app.include_router(auth_router)


@app.get("/", tags=["Root"])
async def root():
    body = {
        "name": "SENTINEL",
        "tagline": "We don't scan files. We understand them.",
        "version": settings.APP_VERSION,
    }
    if settings.docs_enabled:
        body["docs"] = "/docs"
    return body
