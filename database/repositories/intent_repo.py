"""Repository for classified Intent documents."""
from typing import Any, Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.schemas.intent import Intent, IntentTactic
from database.models import dict_to_document, document_to_dict
from backend.app.core.logging import get_logger

logger = get_logger("database.intent_repo")


class IntentRepository:
    """CRUD operations for classified attacker intents."""

    def __init__(self, db: Optional[AsyncIOMotorDatabase] = None):
        self.db = db
        self._memory_store: List[Dict[str, Any]] = []

    async def insert(self, intent: Intent) -> Intent:
        """Insert a classified intent."""
        doc = intent.model_dump()
        if self.db is not None:
            try:
                await self.db.intents.insert_one(dict_to_document(doc))
                return intent
            except Exception as exc:
                logger.error("Error inserting intent in MongoDB: %s", exc)

        self._memory_store.append(doc)
        return intent

    async def insert_many(self, intents: List[Intent]) -> int:
        """Bulk insert multiple intent records."""
        if not intents:
            return 0
        docs = [i.model_dump() for i in intents]
        if self.db is not None:
            try:
                mongo_docs = [dict_to_document(d) for d in docs]
                res = await self.db.intents.insert_many(mongo_docs, ordered=False)
                return len(res.inserted_ids)
            except Exception as exc:
                logger.error("Error bulk inserting intents in MongoDB: %s", exc)

        self._memory_store.extend(docs)
        return len(docs)

    async def list_by_session(self, session_id: str) -> List[Intent]:
        """Fetch all intents classified for a specific session."""
        if self.db is not None:
            try:
                cursor = self.db.intents.find({"session_id": session_id})
                docs = await cursor.to_list(length=100)
                return [Intent(**document_to_dict(d)) for d in docs]
            except Exception as exc:
                logger.error("Error fetching intents for session %s from MongoDB: %s", session_id, exc)

        return [Intent(**d) for d in self._memory_store if d.get("session_id") == session_id]

    async def list_intents(
        self,
        tactic: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Intent]:
        """List classified intents with optional tactic filter."""
        query: Dict[str, Any] = {}
        if tactic:
            query["intent"] = tactic

        if self.db is not None:
            try:
                cursor = self.db.intents.find(query).skip(skip).limit(limit).sort("timestamp", -1)
                docs = await cursor.to_list(length=limit)
                return [Intent(**document_to_dict(d)) for d in docs]
            except Exception as exc:
                logger.error("Error listing intents from MongoDB: %s", exc)

        results = self._memory_store
        if tactic:
            results = [i for i in results if i.get("intent") == tactic]
        results = sorted(results, key=lambda x: x.get("timestamp", ""), reverse=True)
        paginated = results[skip : skip + limit]
        return [Intent(**i) for i in paginated]

    async def count(self) -> int:
        """Count total classified intent records."""
        if self.db is not None:
            try:
                return await self.db.intents.count_documents({})
            except Exception as exc:
                logger.error("Error counting intents in MongoDB: %s", exc)
        return len(self._memory_store)
