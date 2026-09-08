"""Attacker Intent schema and MITRE ATT&CK tactic classifications."""
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class IntentTactic(str, Enum):
    """Categorized attacker intent tactics aligned with MITRE ATT&CK."""

    RECONNAISSANCE = "Reconnaissance / Discovery"
    CREDENTIAL_ACCESS = "Credential Access"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    PERSISTENCE = "Persistence"
    EXECUTION = "Execution"
    DEFENSE_EVASION = "Defense Evasion"
    LATERAL_MOVEMENT = "Lateral Movement"
    DATA_EXFILTRATION = "Data Exfiltration"
    DESTRUCTION_TAMPERING = "Destruction / Tampering"


class Intent(BaseModel):
    """Classified intent with confidence score and MITRE attribution."""

    intent: IntentTactic
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    matched_command: str
    rule: str
    session_id: str
    mitre_technique: Optional[str] = None
    mitre_id: Optional[str] = None
    timestamp: Optional[str] = None
