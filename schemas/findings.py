"""
Schemas for Agent Findings and Knowledge Findings.
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EvidenceStrength(str, Enum):
    DIRECT_EVIDENCE = "DIRECT_EVIDENCE"
    CORRELATED_EVIDENCE = "CORRELATED_EVIDENCE"
    HISTORICAL_EVIDENCE = "HISTORICAL_EVIDENCE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"


class FindingType(str, Enum):
    ERROR_PATTERN = "ERROR_PATTERN"
    METRIC_ANOMALY = "METRIC_ANOMALY"
    DEPLOYMENT_CORRELATION = "DEPLOYMENT_CORRELATION"
    DEPENDENCY_BOTTLENECK = "DEPENDENCY_BOTTLENECK"
    HISTORICAL_MATCH = "HISTORICAL_MATCH"
    GENERAL = "GENERAL"


class AgentFinding(BaseModel):
    """Structured observation produced by specialized investigation agents."""
    agent_name: str = Field(..., description="Name of the agent generating the finding")
    finding_type: FindingType = Field(default=FindingType.GENERAL)
    evidence_strength: EvidenceStrength = Field(default=EvidenceStrength.CORRELATED_EVIDENCE)
    summary: str = Field(..., description="Concise statement of the technical observation")
    supporting_evidence: List[str] = Field(default_factory=list, description="Specific telemetry data or log lines")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    affected_service: Optional[str] = None
    affected_endpoint: Optional[str] = None
    timestamp_range: Optional[Dict[str, str]] = None
    related_error_codes: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)


class KnowledgeFinding(BaseModel):
    """Structured historical or runbook context retrieved by Knowledge / RAG Agent."""
    source_id: str = Field(..., description="Identifier or filename of source document")
    source_type: str = Field(..., description="runbook, architecture, or historical_incident")
    title: str = Field(..., description="Title of the document")
    relevant_excerpt_summary: str = Field(..., description="Key technical summary extracted")
    similarity_score: float = Field(default=0.8, ge=0.0, le=1.0)
    relevance_reason: str = Field(..., description="Why this knowledge applies to the incident")
    associated_failure_pattern: str = Field(..., description="Identified failure pattern")
    recommended_checks: List[str] = Field(default_factory=list)
