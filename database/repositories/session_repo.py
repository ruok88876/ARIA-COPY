"""Repository for Session documents."""
from typing import Any, Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.schemas.session import Session
from database.models import dict_to_document, document_to_dict
from backend.app.core.logging import get_logger

logger = get_logger("database.session_repo")


class SessionRepository:
    """CRUD operations for honeypot attack sessions with MongoDB & in-memory fallback."""

    def __init__(self, db: Optional[AsyncIOMotorDatabase] = None):
        self.db = db
        # In-memory storage for test/offline fallback
        self._memory_store: Dict[str, Dict[str, Any]] = {}

    async def upsert(self, session: Session) -> Session:
        """Insert or update a session by session_id."""
        doc = session.model_dump()
        if self.db is not None:
            try:
                await self.db.sessions.update_one(
                    {"session_id": session.session_id},
                    {"$set": dict_to_document(doc)},
                    upsert=True,
                )
                return session
            except Exception as exc:
                logger.error("Error upserting session %s in MongoDB: %s", session.session_id, exc)

        # Fallback to in-memory store
        self._memory_store[session.session_id] = doc
        return session

    async def get_by_id(self, session_id: str) -> Optional[Session]:
        """Fetch a session by its session_id."""
        if self.db is not None:
            try:
                raw = await self.db.sessions.find_one({"session_id": session_id})
                if raw:
                    return Session(**document_to_dict(raw))
            except Exception as exc:
                logger.error("Error fetching session %s from MongoDB: %s", session_id, exc)

        # Check in-memory store
        raw = self._memory_store.get(session_id)
        if raw:
            return Session(**raw)
        return None

    async def list_sessions(
        self,
        skip: int = 0,
        limit: int = 50,
        attacker_ip: Optional[str] = None,
    ) -> List[Session]:
        """List sessions with optional filtering and pagination."""
        query: Dict[str, Any] = {}
        if attacker_ip:
            query["attacker_ip"] = attacker_ip

        if self.db is not None:
            try:
                cursor = self.db.sessions.find(query).skip(skip).limit(limit).sort("start_time", -1)
                docs = await cursor.to_list(length=limit)
                return [Session(**document_to_dict(d)) for d in docs]
            except Exception as exc:
                logger.error("Error listing sessions from MongoDB: %s", exc)

        # Memory store fallback
        results = list(self._memory_store.values())
        if attacker_ip:
            results = [s for s in results if s.get("attacker_ip") == attacker_ip]
        # Sort descending by start_time
        results.sort(key=lambda s: s.get("start_time", ""), reverse=True)
        paginated = results[skip : skip + limit]
        return [Session(**s) for s in paginated]

    async def count(self) -> int:
        """Count total sessions."""
        if self.db is not None:
            try:
                return await self.db.sessions.count_documents({})
            except Exception as exc:
                logger.error("Error counting sessions in MongoDB: %s", exc)
        return len(self._memory_store)

    async def delete(self, session_id: str) -> bool:
        """Delete a session by session_id."""
        deleted = False
        if self.db is not None:
            try:
                res = await self.db.sessions.delete_one({"session_id": session_id})
                deleted = res.deleted_count > 0
            except Exception as exc:
                logger.error("Error deleting session %s from MongoDB: %s", session_id, exc)

        if session_id in self._memory_store:
            del self._memory_store[session_id]
            deleted = True

        return deleted
