"""
Schemas for Incident Reports, Blast Radius, and Timelines.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from schemas.findings import KnowledgeFinding
from schemas.validation import HypothesisValidation


class TimelineEvent(BaseModel):
    """Deterministic timestamped event in the incident chronological sequence."""
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    event_type: str = Field(..., description="DEPLOYMENT, ERROR_SPIKE, LATENCY_INCREASE, ALERT, etc.")
    description: str = Field(..., description="Event description")
    source: str = Field(default="telemetry", description="logging, monitoring, cloud_run, trace")


class BlastRadiusResult(BaseModel):
    """Blast radius assessment produced by Blast Radius Agent."""
    primary_service: str = Field(..., description="Originating or primary affected service")
    affected_services: List[str] = Field(default_factory=list)
    affected_endpoints: List[str] = Field(default_factory=list)
    region: str = Field(default="us-central1")
    affected_revision: Optional[str] = None
    dependency_impact: List[str] = Field(default_factory=list)
    estimated_scope: str = Field(..., description="Human-readable scope description")
    classification: str = Field(..., description="LOCALIZED, SERVICE_LEVEL, MULTI_SERVICE, REGIONAL, SYSTEM_WIDE")
    evidence: List[str] = Field(default_factory=list)


class IncidentReport(BaseModel):
    """Comprehensive structured incident report produced by Report Agent."""
    incident_id: str
    severity: str
    start_time: str
    end_time: str
    affected_services: List[str]
    affected_endpoints: List[str]
    primary_symptoms: List[str]
    timeline: List[TimelineEvent] = Field(default_factory=list)
    root_cause: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    supporting_evidence: List[str] = Field(default_factory=list)
    contradictory_evidence: List[str] = Field(default_factory=list)
    validated_hypotheses: List[HypothesisValidation] = Field(default_factory=list)
    rejected_hypotheses: List[HypothesisValidation] = Field(default_factory=list)
    blast_radius: BlastRadiusResult
    similar_historical_incidents: List[KnowledgeFinding] = Field(default_factory=list)
    recommended_next_action: str
    missing_evidence: List[str] = Field(default_factory=list)
    investigation_summary: str
