"""Investigation-platform models: graph, confidence, quality, why/why-not.

All views derive from stored RCA structures (InvestigationState, validations,
code findings, approvals, PRs, verification) — no parallel duplicate models.
"""
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class InvestigationNode(BaseModel):
    id: str
    type: str = Field(description="INCIDENT|EVIDENCE|AGENT|HYPOTHESIS|CODE|ROOT_CAUSE|FIX|APPROVAL|PR|VERIFICATION|DEPLOYMENT")
    label: str
    confidence: Optional[float] = None
    status: str = ""
    metadata: Dict = Field(default_factory=dict)


class InvestigationEdge(BaseModel):
    from_id: str = Field(alias="from")
    to_id: str = Field(alias="to")
    relationship: str = Field(description="SUPPORTS|CONTRADICTS|CORRELATES_WITH|CAUSED_BY|LOCATED_IN|CHANGED_BY|VALIDATED_BY|FIXED_BY|CREATED_PR")

    model_config = {"populate_by_name": True}


class InvestigationGraph(BaseModel):
    incident_id: str
    nodes: List[InvestigationNode] = Field(default_factory=list)
    edges: List[InvestigationEdge] = Field(default_factory=list)


class ConfidenceSnapshot(BaseModel):
    stage: str
    confidence: float
    reason: str
    evidence_added: List[str] = Field(default_factory=list)
    provenance: str = ""
    at: str = ""


class AgentFindingView(BaseModel):
    agent: str
    strength: str
    summary: str
    evidence_count: int = 0
    confidence: float = 0.0
    verdict: str = ""


class QualityFactor(BaseModel):
    name: str
    points: float
    max_points: float
    status: str
    note: str


class QualityScore(BaseModel):
    score: float
    max_score: float = 100.0
    root_cause_confidence: Optional[float] = None
    factors: List[QualityFactor] = Field(default_factory=list)
    deductions: List[str] = Field(default_factory=list)


class WhyNotItem(BaseModel):
    hypothesis: str
    category: str
    status: str
    reason: str
    confidence: float = 0.0


class WhyThisView(BaseModel):
    conclusion: str
    category: str
    confidence: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    rejected: List[WhyNotItem] = Field(default_factory=list)


class CodeCorrelation(BaseModel):
    available: bool
    score: Optional[float] = None
    level: str = ""
    checks: List[Dict] = Field(default_factory=list)
    primary_suspect: str = ""
    reason: str = ""


class CausalLink(BaseModel):
    step: int
    title: str
    detail: str
    derived_from: str = ""


class ContributingFactor(BaseModel):
    factor: str
    derived_from: str = ""


class SimilarIncidentMatch(BaseModel):
    incident_id: str
    similarity: float
    root_cause: str = ""
    root_cause_category: str = ""
    service: str = ""
    final_status: str = ""
    remediation: Optional[dict] = None
    matched_on: List[str] = Field(default_factory=list)


class ChallengeAnswer(BaseModel):
    answer: str
    evidence_refs: List[str] = Field(default_factory=list)
    confidence: float = 0.0
    limitations: List[str] = Field(default_factory=list)
