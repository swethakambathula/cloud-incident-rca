"""
RCAResult Pydantic Schema.
Captures the structured Root Cause Analysis report produced by the Gemini RCA Agent.
"""
from typing import List
from pydantic import BaseModel, Field


class RCAResult(BaseModel):
    """Structured Root Cause Analysis result."""
    incident_id: str = Field(..., description="Incident identifier under investigation")
    root_cause: str = Field(..., description="Clear explanation of the confirmed or primary root cause")
    root_cause_category: str = Field(
        ...,
        description="Category: e.g. database_connectivity, connection_pool_exhaustion, faulty_revision, dependency_failure, traffic_overload, configuration_regression, or unknown"
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Calibrated confidence score between 0.0 and 1.0 based on evidence strength"
    )
    evidence: List[str] = Field(
        default_factory=list,
        description="Concrete observed evidence facts supporting this root cause"
    )
    contradictory_evidence: List[str] = Field(
        default_factory=list,
        description="Signals that contradict alternative hypotheses (e.g. CPU normal rules out CPU saturation)"
    )
    affected_services: List[str] = Field(
        default_factory=list,
        description="List of services impacted by this incident"
    )
    blast_radius: str = Field(
        ...,
        description="Description of blast radius (e.g., localized to /checkout, service-wide, all downstream clients)"
    )
    recommended_action: str = Field(
        ...,
        description="Recommended operational remediation or immediate stabilization action"
    )
    remediation_risk: str = Field(
        ...,
        description="Risk level of recommended action: LOW, MEDIUM, or HIGH"
    )
    additional_checks_required: List[str] = Field(
        default_factory=list,
        description="Next investigation steps or verifications to confirm hypothesis"
    )
