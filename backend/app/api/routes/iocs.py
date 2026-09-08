"""Indicator of Compromise (IOC) API routes."""
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from backend.app.schemas.ioc import IOC, IOCType
from backend.app.services.pipeline_service import get_ioc_repository

router = APIRouter(prefix="/iocs", tags=["IOCs"])


@router.get("", response_model=List[IOC])
async def list_iocs(
    type: Optional[IOCType] = Query(None, description="Filter by IOC type (ipv4, domain, url, md5, sha1, sha256, file_path)"),
    session_id: Optional[str] = Query(None, description="Filter by originating session ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
):
    """List extracted Indicators of Compromise."""
    repo = await get_ioc_repository()
    return await repo.list_iocs(ioc_type=type, session_id=session_id, skip=skip, limit=limit)


@router.get("/lookup", response_model=IOC)
async def lookup_ioc(
    value: str = Query(..., description="Exact IOC string value"),
    type: Optional[IOCType] = Query(None, description="Optional IOC type filter"),
):
    """Look up an individual IOC by exact value."""
    repo = await get_ioc_repository()
    ioc = await repo.get_by_value(value=value, ioc_type=type)
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"IOC '{value}' not found",
        )
    return ioc
