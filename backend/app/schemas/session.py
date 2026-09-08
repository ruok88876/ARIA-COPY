"""Honeypot Session and Command schemas."""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.schemas.ioc import IOC
from backend.app.schemas.intent import Intent


class Command(BaseModel):
    """Command executed inside a honeypot session."""

    command: str
    timestamp: str
    session_id: str


class Session(BaseModel):
    """Aggregated attack session captured by honeypot and SDN telemetry."""

    session_id: str
    attacker_ip: str
    attacker_port: Optional[int] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    start_time: str
    end_time: Optional[str] = None
    duration: float = Field(default=0.0, description="Session duration in seconds")
    username: Optional[str] = None
    authentication_status: str = Field(
        default="none",
        description="Auth status: 'none', 'success', 'failed'"
    )
    commands: List[Command] = Field(default_factory=list)
    iocs: List[IOC] = Field(default_factory=list)
    intents: List[Intent] = Field(default_factory=list)
    downloaded_files: List[Dict[str, Any]] = Field(default_factory=list)
    is_closed: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
