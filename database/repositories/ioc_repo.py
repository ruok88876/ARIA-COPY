"""Repository for Indicator of Compromise (IOC) documents."""
from typing import Any, Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.schemas.ioc import IOC, IOCType
from database.models import dict_to_document, document_to_dict
from backend.app.core.logging import get_logger

logger = get_logger("database.ioc_repo")


class IOCRepository:
    """CRUD operations for extracted Indicators of Compromise."""

    def __init__(self, db: Optional[AsyncIOMotorDatabase] = None):
        self.db = db
        # In-memory storage keyed by (value, type)
        self._memory_store: Dict[str, Dict[str, Any]] = {}

    def _make_key(self, value: str, ioc_type: str) -> str:
        return f"{ioc_type.lower()}:{value.lower()}"

    async def upsert(self, ioc: IOC) -> IOC:
        """Upsert an IOC, updating metadata and last seen timestamp if existing."""
        doc = ioc.model_dump()
        ioc_type_str = ioc.type.value if hasattr(ioc.type, "value") else str(ioc.type)
        key = self._make_key(ioc.value, ioc_type_str)

        filter_query = {
            "value": ioc.value,
            "type": ioc_type_str,
        }

        # Build $set without the top-level 'metadata' object to prevent conflict with $addToSet on 'metadata.sessions'
        set_fields: Dict[str, Any] = {
            "value": ioc.value,
            "type": ioc_type_str,
            "session_id": ioc.session_id,
            "source": ioc.source,
            "timestamp": ioc.timestamp,
            "is_internal": ioc.is_internal,
        }

        meta_dict = doc.get("metadata", {})
        if isinstance(meta_dict, dict):
            for k, v in meta_dict.items():
                if k != "sessions":
                    set_fields[f"metadata.{k}"] = v

        # Collect session IDs to add to metadata.sessions
        sessions_to_add: List[str] = []
        if ioc.session_id:
            sessions_to_add.append(ioc.session_id)
        if isinstance(meta_dict, dict) and "sessions" in meta_dict and isinstance(meta_dict["sessions"], list):
            for s in meta_dict["sessions"]:
                if s and s not in sessions_to_add:
                    sessions_to_add.append(s)

        update_query: Dict[str, Any] = {
            "$set": set_fields,
            "$addToSet": {
                "metadata.sessions": {
                    "$each": sessions_to_add
                } if len(sessions_to_add) > 1 else (sessions_to_add[0] if sessions_to_add else ioc.session_id)
            },
        }

        if self.db is not None:
            try:
                await self.db.iocs.update_one(
                    filter_query,
                    update_query,
                    upsert=True,
                )
            except Exception as exc:
                logger.error("Error upserting IOC in MongoDB: %s", exc)

        # In-memory fallback / tracking
        if key in self._memory_store:
            existing = self._memory_store[key]
            sessions = set(existing.get("metadata", {}).get("sessions", []))
            for s in sessions_to_add:
                sessions.add(s)
            doc["metadata"]["sessions"] = list(sessions)
        else:
            doc["metadata"]["sessions"] = list(sessions_to_add)

        self._memory_store[key] = doc
        ioc.metadata["sessions"] = doc["metadata"]["sessions"]
        return ioc

    async def upsert_many(self, iocs: List[IOC]) -> int:
        """Upsert a list of IOCs."""
        count = 0
        for ioc in iocs:
            await self.upsert(ioc)
            count += 1
        return count

    async def get_by_value(self, value: str, ioc_type: Optional[IOCType] = None) -> Optional[IOC]:
        """Fetch an IOC by exact value and optional type."""
        query: Dict[str, Any] = {"value": value}
        if ioc_type:
            query["type"] = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)

        if self.db is not None:
            try:
                raw = await self.db.iocs.find_one(query)
                if raw:
                    return IOC(**document_to_dict(raw))
            except Exception as exc:
                logger.error("Error fetching IOC %s from MongoDB: %s", value, exc)

        # In-memory search
        for doc in self._memory_store.values():
            if doc.get("value") == value:
                if not ioc_type or doc.get("type") == (ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)):
                    return IOC(**doc)
        return None

    async def list_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        session_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[IOC]:
        """List IOCs with pagination and optional filters."""
        query: Dict[str, Any] = {}
        if ioc_type:
            query["type"] = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
        if session_id:
            query["$or"] = [
                {"session_id": session_id},
                {"metadata.sessions": session_id},
            ]

        if self.db is not None:
            try:
                cursor = self.db.iocs.find(query).skip(skip).limit(limit).sort("timestamp", -1)
                docs = await cursor.to_list(length=limit)
                return [IOC(**document_to_dict(d)) for d in docs]
            except Exception as exc:
                logger.error("Error listing IOCs from MongoDB: %s", exc)

        results = list(self._memory_store.values())
        if ioc_type:
            target_type = ioc_type.value if hasattr(ioc_type, "value") else str(ioc_type)
            results = [i for i in results if i.get("type") == target_type]
        if session_id:
            results = [
                i for i in results
                if i.get("session_id") == session_id or session_id in i.get("metadata", {}).get("sessions", [])
            ]
        results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        paginated = results[skip : skip + limit]
        return [IOC(**i) for i in paginated]

    async def count(self) -> int:
        """Count total unique IOCs."""
        if self.db is not None:
            try:
                return await self.db.iocs.count_documents({})
            except Exception as exc:
                logger.error("Error counting IOCs in MongoDB: %s", exc)
        return len(self._memory_store)
