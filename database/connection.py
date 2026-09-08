"""MongoDB connection management using Motor (async) with graceful fallbacks."""
import asyncio
from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

from backend.app.core.config import get_settings
from backend.app.core.logging import get_logger

logger = get_logger("database.connection")

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None
_connection_attempted: bool = False
_is_available: bool = False


async def get_mongo_client(force: bool = False) -> Optional[AsyncIOMotorClient]:
    """Get or create singleton Motor MongoDB client."""
    global _client, _connection_attempted, _is_available
    if _connection_attempted and not force:
        return _client

    _connection_attempted = True
    settings = get_settings()
    try:
        candidate_client = AsyncIOMotorClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=min(settings.mongodb_timeout_ms, 1000),
            connectTimeoutMS=min(settings.mongodb_timeout_ms, 1000),
        )
        # Test server connection with short ping
        await candidate_client.admin.command("ping")
        _client = candidate_client
        _is_available = True
        logger.info("Successfully connected to MongoDB at %s", settings.mongodb_uri)
    except (ConnectionFailure, ServerSelectionTimeoutError) as exc:
        _client = None
        _is_available = False
        logger.warning(
            "MongoDB is not reachable at %s (%s). Operating in offline/degraded mode.",
            settings.mongodb_uri,
            exc,
        )
    except Exception as exc:
        _client = None
        _is_available = False
        logger.error("Unexpected error connecting to MongoDB: %s", exc)

    return _client


async def get_database() -> Optional[AsyncIOMotorDatabase]:
    """Get active MongoDB database instance, or None if offline."""
    global _db
    if _db is not None:
        return _db
    client = await get_mongo_client()
    if client is not None:
        settings = get_settings()
        _db = client[settings.mongodb_database]
    return _db


async def is_mongo_available() -> bool:
    """Check if MongoDB is currently reachable."""
    global _is_available
    if not _connection_attempted:
        await get_mongo_client()
    return _is_available


async def init_indexes() -> bool:
    """Initialize necessary indexes on MongoDB collections."""
    db = await get_database()
    if db is None:
        logger.warning("Skipping index initialization because MongoDB is offline.")
        return False

    try:
        # Sessions collection indexes
        await db.sessions.create_index("session_id", unique=True)
        await db.sessions.create_index("attacker_ip")
        await db.sessions.create_index("start_time")

        # Logs collection indexes
        await db.logs.create_index("session")
        await db.logs.create_index("eventid")
        await db.logs.create_index("timestamp")

        # IOCs collection indexes
        await db.iocs.create_index([("value", 1), ("type", 1)], unique=True)
        await db.iocs.create_index("session_id")
        await db.iocs.create_index("type")

        # Intents collection indexes
        await db.intents.create_index("session_id")
        await db.intents.create_index("intent")

        # SDN events collection indexes
        await db.sdn_events.create_index("attacker_ip")
        await db.sdn_events.create_index("timestamp")

        logger.info("Successfully created indexes across all MongoDB collections.")
        return True
    except Exception as exc:
        logger.error("Error creating MongoDB indexes: %s", exc)
        return False


async def close_mongo_connection() -> None:
    """Close active MongoDB client connection."""
    global _client, _db, _connection_attempted, _is_available
    if _client is not None:
        _client.close()
    _client = None
    _db = None
    _connection_attempted = False
    _is_available = False
    logger.info("Closed MongoDB connection.")
