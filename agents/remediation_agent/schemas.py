"""
RemediationPlan schemas for Phase 4.
"""
from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum

class MitigationType(str, Enum):
    TEMPORARY_MITIGATION = "TEMPORARY_MITIGATION"
    PERMANENT_FIX = "PERMANENT_FIX"
    WORKAROUND = "WORKAROUND"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class RemediationPlan(BaseModel):
    incident_id: str
    root_cause: str
    root_cause_category: str
    recommended_action: str  # e.g. cloud_run_rollback
    alternative_actions: List[str] = Field(default_factory=list)
    mitigation_type: MitigationType
    expected_effect: str
    estimated_risk: RiskLevel
    reversibility: str  # e.g. reversible via traffic shift
    required_permissions: List[str] = Field(default_factory=list)
    preconditions: List[str] = Field(default_factory=list)
    rollback_plan: str
    verification_plan: str
    confidence: float = Field(ge=0.0, le=0.99)
    human_approval_required: bool = True
    target_resource: Optional[str] = None  # e.g. projects/*/services/checkout-service
    target_revision: Optional[str] = None
