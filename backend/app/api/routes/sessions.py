"""Sessions API routes."""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.schemas.session import Session
from backend.app.services.pipeline_service import get_session_repository

router = APIRouter(prefix="/sessions", tags=["Sessions"])


@router.get("", response_model=List[Session])
async def list_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    attacker_ip: Optional[str] = Query(None, description="Filter by attacker IP"),
):
    """List attack sessions with pagination and filtering."""
    repo = await get_session_repository()
    return await repo.list_sessions(skip=skip, limit=limit, attacker_ip=attacker_ip)


@router.get("/{session_id}", response_model=Session)
async def get_session(session_id: str):
    """Retrieve detailed session metadata, executed commands, IOCs, and classified intents."""
    repo = await get_session_repository()
    session = await repo.get_by_id(session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )
    return session


@router.delete("/{session_id}", status_code=status.HTTP_200_OK)
async def delete_session(session_id: str):
    """Delete a session by session ID."""
    repo = await get_session_repository()
    deleted = await repo.delete(session_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found",
        )
    return {"message": f"Session '{session_id}' successfully deleted"}
