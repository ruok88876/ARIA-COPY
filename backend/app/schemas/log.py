"""Cowrie log event schema."""
from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class CowrieEvent(BaseModel):
    """Normalized representation of a single Cowrie honeypot event."""

    eventid: str
    timestamp: str
    session: str
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    message: Optional[str] = None
    input: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    outfile: Optional[str] = None
    shasum: Optional[str] = None
    url: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)
