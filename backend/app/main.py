"""SENTINEL — FastAPI Application Entry Point.

The autonomous threat intelligence platform API server.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import engine, Base
from app.api.routes import router, auth_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — create tables on startup."""
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
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── CORS Middleware ──────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
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
