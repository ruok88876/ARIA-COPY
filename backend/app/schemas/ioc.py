"""Indicator of Compromise (IOC) schema."""
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    """Supported observable IOC types."""

    IPV4 = "ipv4"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILE_PATH = "file_path"


class IOC(BaseModel):
    """Observable Indicator of Compromise extracted from attack telemetry."""

    type: IOCType
    value: str
    session_id: str
    source: str = Field(
        default="command",
        description="Source of IOC, e.g., 'command', 'file_download', 'network'"
    )
    timestamp: str
    is_internal: bool = Field(
        default=False,
        description="True if IP/domain is RFC1918 or local loopback"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)
