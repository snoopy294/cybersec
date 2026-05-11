"""SENTINEL — FastAPI Application Entry Point.

The autonomous threat intelligence platform API server.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import engine, Base
from app.api.routes import router, auth_router
from app.services.file_service import validate_storage_configuration
from app.services.security_service import validate_runtime_security

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — create tables on startup."""
    validate_runtime_security(settings)
    validate_storage_configuration()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title="SENTINEL API",
    description=(
        "The Autonomous Threat Intelligence Platform. "
        "Upload suspicious files, receive AI-powered threat analysis in under 60 seconds."
    ),
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.EXPOSE_API_DOCS else None,
    redoc_url="/redoc" if settings.EXPOSE_API_DOCS else None,
    lifespan=lifespan,
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    if not settings.DEBUG:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# ── CORS Middleware ──────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Route Registration ──────────────────────────────────────────
app.include_router(router)
app.include_router(auth_router)


@app.get("/", tags=["Root"])
async def root():
    return {
        "name": "SENTINEL",
        "tagline": "We don't scan files. We understand them.",
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }
