"""SDN Network Telemetry Event schema."""
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, Field


class SDNEvent(BaseModel):
    """Network-level event captured by the OpenFlow switch and SDN controller."""

    attacker_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "TCP"
    switch_id: Optional[Union[int, str]] = None
    timestamp: str
    ssh_detected: bool = False
    redirected: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
