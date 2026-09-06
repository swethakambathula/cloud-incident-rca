"""
VerificationResult schemas
"""
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum

class VerificationStatus(str, Enum):
    RESOLVED = "RESOLVED"
    PARTIALLY_RESOLVED = "PARTIALLY_RESOLVED"
    NOT_RESOLVED = "NOT_RESOLVED"
    REGRESSED = "REGRESSED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

class VerificationResult(BaseModel):
    incident_id: str
    execution_id: str
    verification_status: VerificationStatus
    metrics_before: dict = Field(default_factory=dict)
    metrics_after: dict = Field(default_factory=dict)
    error_rate_before: float = 0.0
    error_rate_after: float = 0.0
    latency_before: float = 0.0
    latency_after: float = 0.0
    service_health_before: str = "UNKNOWN"
    service_health_after: str = "UNKNOWN"
    customer_impact_before: str = "UNKNOWN"
    customer_impact_after: str = "UNKNOWN"
    resolved: bool = False
    partial_recovery: bool = False
    new_issues_detected: bool = False
    verification_confidence: float = Field(ge=0.0, le=1.0, default=0.85)
    summary: str = ""
