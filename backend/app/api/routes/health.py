"""Health check and status API route."""
from fastapi import APIRouter
from backend.app.core.config import get_settings
from database.connection import is_mongo_available

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """System health and operational status."""
    settings = get_settings()
    mongo_up = await is_mongo_available()

    return {
        "status": "healthy" if mongo_up else "degraded",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "database": {
            "status": "connected" if mongo_up else "offline",
            "name": settings.mongodb_database,
        },
    }
