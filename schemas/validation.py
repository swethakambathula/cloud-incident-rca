"""
Schema for Critic / Validator Agent Hypothesis Validation.
"""
from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class ValidationStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    WEAK = "WEAK"
    REJECTED = "REJECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class HypothesisValidation(BaseModel):
    """Independent review output produced by Critic / Validator Agent."""
    hypothesis_id: str = Field(..., description="Target hypothesis ID being evaluated")
    validation_status: ValidationStatus = Field(..., description="Verdict on the hypothesis")
    accepted: bool = Field(..., description="True if hypothesis is supported and plausible")
    adjusted_confidence: float = Field(..., ge=0.0, le=0.99, description="Recalibrated confidence after critical analysis")
    supporting_evidence_strength: str = Field(..., description="STRONG, MODERATE, WEAK, or NONE")
    contradictions: List[str] = Field(default_factory=list, description="Explicit contradictory signals discovered")
    missing_checks: List[str] = Field(default_factory=list, description="Checks that remain unverified")
    critic_reasoning: str = Field(..., description="SRE critique explaining acceptance, rejection, or caveats")
    additional_investigation_required: List[str] = Field(
        default_factory=list,
        description="Specific tasks to request if status is INSUFFICIENT_EVIDENCE or PARTIALLY_SUPPORTED"
    )
