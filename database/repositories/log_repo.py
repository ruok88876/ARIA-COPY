"""Repository for raw Cowrie Log events."""
from typing import Any, Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.schemas.log import CowrieEvent
from database.models import dict_to_document, document_to_dict
from backend.app.core.logging import get_logger

logger = get_logger("database.log_repo")


class LogRepository:
    """CRUD operations for Cowrie raw and normalized log events."""

    def __init__(self, db: Optional[AsyncIOMotorDatabase] = None):
        self.db = db
        self._memory_store: List[Dict[str, Any]] = []

    async def insert(self, event: CowrieEvent) -> CowrieEvent:
        """Insert a single Cowrie log event."""
        doc = event.model_dump()
        if self.db is not None:
            try:
                await self.db.logs.insert_one(dict_to_document(doc))
                return event
            except Exception as exc:
                logger.error("Error inserting log event in MongoDB: %s", exc)

        self._memory_store.append(doc)
        return event

    async def insert_many(self, events: List[CowrieEvent]) -> int:
        """Bulk insert multiple Cowrie log events."""
        if not events:
            return 0
        docs = [e.model_dump() for e in events]
        inserted = 0
        if self.db is not None:
            try:
                mongo_docs = [dict_to_document(d) for d in docs]
                res = await self.db.logs.insert_many(mongo_docs, ordered=False)
                inserted = len(res.inserted_ids)
                return inserted
            except Exception as exc:
                logger.error("Error bulk inserting logs in MongoDB: %s", exc)

        self._memory_store.extend(docs)
        return len(docs)

    async def list_logs(
        self,
        session_id: Optional[str] = None,
        eventid: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[CowrieEvent]:
        """List log events with optional filters."""
        query: Dict[str, Any] = {}
        if session_id:
            query["session"] = session_id
        if eventid:
            query["eventid"] = eventid

        if self.db is not None:
            try:
                cursor = self.db.logs.find(query).skip(skip).limit(limit).sort("timestamp", -1)
                docs = await cursor.to_list(length=limit)
                return [CowrieEvent(**document_to_dict(d)) for d in docs]
            except Exception as exc:
                logger.error("Error querying logs from MongoDB: %s", exc)

        results = self._memory_store
        if session_id:
            results = [e for e in results if e.get("session") == session_id]
        if eventid:
            results = [e for e in results if e.get("eventid") == eventid]
        results = sorted(results, key=lambda e: e.get("timestamp", ""), reverse=True)
        paginated = results[skip : skip + limit]
        return [CowrieEvent(**e) for e in paginated]

    async def count(self) -> int:
        """Count total log events."""
        if self.db is not None:
            try:
                return await self.db.logs.count_documents({})
            except Exception as exc:
                logger.error("Error counting logs in MongoDB: %s", exc)
        return len(self._memory_store)
