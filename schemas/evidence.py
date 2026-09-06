"""
IncidentEvidence Pydantic Schema.
Captures normalized, structured telemetry and context across logs, metrics,
revisions, traces, and dependencies for Root Cause Analysis.
"""
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class IncidentEvidence(BaseModel):
    """Normalized evidence model synthesizing signals across Google Cloud services."""
    incident_id: str = Field(..., description="Unique identifier for the incident")
    start_time: str = Field(..., description="ISO 8601 start timestamp of the incident window")
    end_time: str = Field(..., description="ISO 8601 end timestamp of the incident window")
    project_id: str = Field(..., description="Google Cloud project identifier")
    service_name: str = Field(..., description="Target Cloud Run service name")
    revision_name: Optional[str] = Field(None, description="Active Cloud Run revision during incident")
    region: Optional[str] = Field(None, description="Google Cloud region (e.g., us-central1)")
    severity: str = Field(..., description="Incident severity level: P1, P2, or P3")
    symptoms: List[str] = Field(default_factory=list, description="Observed symptom statements")
    application_errors: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Structured application log errors (error_code, message, frequency, etc.)"
    )
    request_errors: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Cloud Run HTTP request failures (status_code, endpoint, count, etc.)"
    )
    latency: Dict[str, Any] = Field(
        default_factory=dict,
        description="Latency metrics: p50, p95, baseline vs incident comparison"
    )
    request_count: Dict[str, Any] = Field(
        default_factory=dict,
        description="Request traffic metrics: total volume, 5xx rate, baseline vs incident"
    )
    cpu_utilization: Dict[str, Any] = Field(
        default_factory=dict,
        description="CPU utilization metrics: baseline, incident, percentage delta, severity"
    )
    memory_utilization: Dict[str, Any] = Field(
        default_factory=dict,
        description="Memory utilization metrics: baseline, incident, percentage delta, severity"
    )
    recent_deployments: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Recent Cloud Run revisions, deployment timestamps, traffic split"
    )
    dependencies: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Downstream and upstream dependency signals (status, latency, errors)"
    )
    traces: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Distributed trace summaries, trace IDs, and span latencies"
    )
    blast_radius: Dict[str, Any] = Field(
        default_factory=dict,
        description="Impact assessment: affected endpoints, dependent services, regional scope"
    )
    raw_evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Audit trail of raw log snippets and metric points collected"
    )
