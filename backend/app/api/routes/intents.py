"""Attacker Intent classification API routes."""
from typing import List, Optional
from fastapi import APIRouter, Query

from backend.app.schemas.intent import Intent
from backend.app.services.pipeline_service import get_intent_repository

router = APIRouter(prefix="/intents", tags=["Intents"])


@router.get("", response_model=List[Intent])
async def list_intents(
    tactic: Optional[str] = Query(None, description="Filter by MITRE tactic (e.g. 'Reconnaissance / Discovery')"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    """List classified attacker intents across all sessions."""
    repo = await get_intent_repository()
    return await repo.list_intents(tactic=tactic, skip=skip, limit=limit)


@router.get("/{session_id}", response_model=List[Intent])
async def get_session_intents(session_id: str):
    """Retrieve all classified intents for a specific attack session."""
    repo = await get_intent_repository()
    return await repo.list_by_session(session_id)
