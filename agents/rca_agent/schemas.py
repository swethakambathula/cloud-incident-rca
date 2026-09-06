"""
Pydantic schemas for Cloud Incident RCA Agent.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime

# Import primary unified schemas
from schemas.evidence import IncidentEvidence
from schemas.rca import RCAResult


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    FATAL = "FATAL"


class LogEntry(BaseModel):
    timestamp: str
    parsed_timestamp: Optional[datetime] = None
    service: str
    level: LogLevel
    message: str
    raw_log: str
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_anomaly: bool = False


class EvidenceItem(BaseModel):
    id: str
    timestamp: str
    source_service: str
    type: str  # e.g., "ERROR_LOG", "METRIC_SPIKE", "CASCADE_TRIGGER", "CONFIG_CHANGE"
    description: str
    raw_excerpt: str
    relevance_score: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentContext(BaseModel):
    incident_id: str
    title: str
    description: str
    services_involved: List[str]
    start_time: str
    end_time: Optional[str] = None
    log_files: List[str]
    symptoms: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    timestamp: str
    service: str
    event_type: str
    summary: str
    is_root_cause_candidate: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class RemediationStep(BaseModel):
    step_number: int
    action: str
    command_or_config: Optional[str] = None
    target_service: str
    priority: str = "HIGH"  # HIGH, MEDIUM, LOW


class RCAResult(BaseModel):
    incident_id: str
    title: str
    root_cause_summary: str
    root_cause_component: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    causal_chain: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    remediation_steps: List[RemediationStep] = Field(default_factory=list)
    prevention_recommendations: List[str] = Field(default_factory=list)
    generated_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    reasoning_mode: str = "DETERMINISTIC_RULES"  # or "LLM_AUGMENTED"


class EvaluationMetric(BaseModel):
    incident_id: str
    root_cause_matched: bool
    component_matched: bool
    confidence: float
    evidence_recall_score: float
    precision_score: float
    notes: str
