"""SDN Network telemetry and status API routes."""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Query, status

from backend.app.schemas.sdn import SDNEvent
from backend.app.services.pipeline_service import get_sdn_repository

router = APIRouter(prefix="/sdn", tags=["SDN Telemetry"])


@router.get("/events", response_model=List[SDNEvent])
async def list_sdn_events(
    attacker_ip: Optional[str] = Query(None, description="Filter by attacker IP"),
    redirected_only: bool = Query(False, description="Filter by redirected traffic only"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    """List network telemetry and redirection events captured by the SDN controller."""
    repo = await get_sdn_repository()
    return await repo.list_events(attacker_ip=attacker_ip, redirected_only=redirected_only, skip=skip, limit=limit)


@router.get("/status")
async def get_sdn_status():
    """Retrieve operational status and statistics of SDN controller and redirection engine."""
    repo = await get_sdn_repository()
    return await repo.get_status_summary()


@router.post("/telemetry", status_code=status.HTTP_201_CREATED, response_model=SDNEvent)
async def ingest_sdn_telemetry(event: SDNEvent):
    """Ingest real-time network telemetry or redirection events emitted by the SDN controller."""
    repo = await get_sdn_repository()
    saved = await repo.insert(event)
    return saved
