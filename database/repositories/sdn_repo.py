"""Repository for SDN network telemetry and redirection events."""
from typing import Any, Dict, List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase

from backend.app.schemas.sdn import SDNEvent
from database.models import dict_to_document, document_to_dict
from backend.app.core.logging import get_logger

logger = get_logger("database.sdn_repo")


class SDNRepository:
    """CRUD and querying for SDN network telemetry events."""

    def __init__(self, db: Optional[AsyncIOMotorDatabase] = None):
        self.db = db
        self._memory_store: List[Dict[str, Any]] = []

    async def insert(self, event: SDNEvent) -> SDNEvent:
        """Insert a new SDN network telemetry event."""
        doc = event.model_dump()
        if self.db is not None:
            try:
                await self.db.sdn_events.insert_one(dict_to_document(doc))
                return event
            except Exception as exc:
                logger.error("Error inserting SDN event in MongoDB: %s", exc)

        self._memory_store.append(doc)
        return event

    async def list_events(
        self,
        attacker_ip: Optional[str] = None,
        redirected_only: bool = False,
        skip: int = 0,
        limit: int = 50,
    ) -> List[SDNEvent]:
        """List SDN events with optional filters."""
        query: Dict[str, Any] = {}
        if attacker_ip:
            query["attacker_ip"] = attacker_ip
        if redirected_only:
            query["redirected"] = True

        if self.db is not None:
            try:
                cursor = self.db.sdn_events.find(query).skip(skip).limit(limit).sort("timestamp", -1)
                docs = await cursor.to_list(length=limit)
                return [SDNEvent(**document_to_dict(d)) for d in docs]
            except Exception as exc:
                logger.error("Error listing SDN events from MongoDB: %s", exc)

        results = self._memory_store
        if attacker_ip:
            results = [e for e in results if e.get("attacker_ip") == attacker_ip]
        if redirected_only:
            results = [e for e in results if e.get("redirected") is True]
        results = sorted(results, key=lambda x: x.get("timestamp", ""), reverse=True)
        paginated = results[skip : skip + limit]
        return [SDNEvent(**e) for e in paginated]

    async def count(self) -> int:
        """Count total SDN events."""
        if self.db is not None:
            try:
                return await self.db.sdn_events.count_documents({})
            except Exception as exc:
                logger.error("Error counting SDN events in MongoDB: %s", exc)
        return len(self._memory_store)

    async def get_status_summary(self) -> Dict[str, Any]:
        """Provide real-time summary statistics of SDN network events."""
        total = await self.count()
        events = await self.list_events(limit=1000)
        redirected_count = sum(1 for e in events if e.redirected)
        ssh_detected_count = sum(1 for e in events if e.ssh_detected)
        unique_attackers = len(set(e.attacker_ip for e in events))

        return {
            "total_events": total,
            "redirected_count": redirected_count,
            "ssh_detected_count": ssh_detected_count,
            "unique_attackers": unique_attackers,
            "status": "active" if total > 0 else "idle",
        }
