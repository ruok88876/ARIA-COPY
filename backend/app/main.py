"""FastAPI Application entrypoint for ARIA Platform."""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger, setup_logging
from database.connection import close_mongo_connection, init_indexes
from backend.app.api.routes import health, sessions, logs, iocs, intents, sdn

logger = get_logger("backend.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    setup_logging()
    logger.info("Initializing ARIA platform services...")

    # Attempt to initialize MongoDB indexes (gracefully continues if offline)
    await init_indexes()

    yield

    logger.info("Shutting down ARIA platform services...")
    await close_mongo_connection()


def create_app() -> FastAPI:
    """Factory creating configured FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="ARIA – Adaptive Reasoning Intelligence for Attack Deception",
        description="Phase 2 Attack Analysis & Threat Intelligence API platform.",
        version=settings.app_version,
        lifespan=lifespan,
    )

    # Configure CORS for dashboard and external consumers
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register root health endpoint
    app.include_router(health.router)

    # Register API v1 endpoints
    app.include_router(health.router, prefix=settings.api_prefix)
    app.include_router(sessions.router, prefix=settings.api_prefix)
    app.include_router(logs.router, prefix=settings.api_prefix)
    app.include_router(iocs.router, prefix=settings.api_prefix)
    app.include_router(intents.router, prefix=settings.api_prefix)
    app.include_router(sdn.router, prefix=settings.api_prefix)

    @app.get("/", tags=["Root"])
    async def root():
        return {
            "name": settings.app_name,
            "version": settings.app_version,
            "docs": "/docs",
            "health": f"{settings.api_prefix}/health",
        }

    return app


app = create_app()
