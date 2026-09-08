"""Honeypot logs API and ingestion routes."""
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.schemas.log import CowrieEvent
from backend.app.services.pipeline_service import get_log_repository, get_pipeline
from honeypot.parser import CowrieParser

router = APIRouter(tags=["Logs & Ingestion"])
_parser = CowrieParser()


@router.get("/logs", response_model=List[CowrieEvent])
async def list_logs(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    eventid: Optional[str] = Query(None, description="Filter by event type"),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
):
    """Query raw and normalized honeypot logs."""
    repo = await get_log_repository()
    return await repo.list_logs(session_id=session_id, eventid=eventid, skip=skip, limit=limit)


@router.post("/logs", status_code=status.HTTP_201_CREATED)
@router.post("/cowrie/log", status_code=status.HTTP_201_CREATED)
async def ingest_cowrie_log(payload: Dict[str, Any]):
    """Ingest a live Cowrie log event, triggering real-time session, IOC, and intent pipeline analysis."""
    # Convert incoming dictionary into a CowrieEvent
    import json
    line = json.dumps(payload)
    event = _parser.parse_line(line)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload could not be parsed into a valid Cowrie event (missing eventid/timestamp/session)",
        )

    pipeline = await get_pipeline()
    result = await pipeline.process_event(event)

    return {
        "status": "ingested",
        "session_id": event.session,
        "eventid": event.eventid,
        "iocs_extracted": result.iocs_extracted,
        "intents_classified": result.intents_classified,
    }
