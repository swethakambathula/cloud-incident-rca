"""
Incident memory schemas
"""
from typing import List, Optional, Any
from pydantic import BaseModel, Field

class IncidentMemoryRecord(BaseModel):
    incident_id: str
    service: str
    symptoms: List[str] = Field(default_factory=list)
    timeline: List[dict] = Field(default_factory=list)
    root_cause: str
    root_cause_category: str
    supporting_evidence: List[str] = Field(default_factory=list)
    rejected_hypotheses: List[str] = Field(default_factory=list)
    blast_radius: dict = Field(default_factory=dict)
    remediation: Optional[dict] = None
    approval_outcome: Optional[str] = None
    execution_result: Optional[dict] = None
    verification_result: Optional[dict] = None
    final_status: str
    timestamps: dict = Field(default_factory=dict)
    confidence: float = 0.0
