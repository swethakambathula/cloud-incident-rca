"""
Project, PullRequest and LogAnalysis schemas (UX platform layer).
"""
from typing import List, Optional
from pydantic import BaseModel, Field


class DataSource(BaseModel):
    kind: str = Field(description="git | gcp | upload")
    status: str = Field(default="connected", description="connected | disconnected | error")
    detail: str = ""


class Project(BaseModel):
    project_id: str
    name: str
    description: str = ""
    environment: str = "production"
    team_owner: str = ""
    repository_url: str = ""
    provider: str = "github"
    default_branch: str = "main"
    local_path: str = ""
    gcp_project_id: str = ""
    region: str = ""
    services: List[str] = Field(default_factory=list)
    status: str = "active"
    sources_config: dict = Field(default_factory=dict,
                                 description="Optional telemetry source hints: log_source, metrics_source, trace_source, deployment_source")
    service_mappings: dict = Field(default_factory=dict,
                                   description="service -> repo path, e.g. checkout-service -> services/checkout/")
    readiness: dict = Field(default_factory=dict,
                            description="Last repository readiness scan result")
    demo_mode: bool = Field(default=False,
                            description="Demo Mode: synthetic evidence, isolated repo, no production impact")
    created_at: str = ""
    last_scan: str = ""
    detected: dict = Field(default_factory=dict)
    data_sources: List[DataSource] = Field(default_factory=list)
    repo_access: str = "READ_ONLY"


class PullRequestRecord(BaseModel):
    pr_id: str
    pr_number: Optional[int] = None
    project_id: str = "unassigned"
    incident_id: str = ""
    repository: str = ""
    branch: str = ""
    base_branch: str = "main"
    commit_sha: str = ""
    title: str = ""
    root_cause: str = ""
    root_cause_category: str = ""
    confidence: float = 0.0
    risk: str = "LOW"
    status: str = "Open"
    tests_status: str = "passed"
    tests_output: str = ""
    files_changed: List[str] = Field(default_factory=list)
    additions: int = 0
    deletions: int = 0
    diff: str = ""
    supporting_evidence: List[str] = Field(default_factory=list)
    approval_id: str = ""
    approved_by: str = ""
    approved_at: str = ""
    created_at: str = ""
    created_by: str = "rca-agent"
    external_url: str = ""


class UploadedFile(BaseModel):
    filename: str
    size_bytes: int = 0
    detected_format: str = ""
    detected_source: str = ""
    record_count: int = 0
    time_start: str = ""
    time_end: str = ""
    parse_status: str = ""
    parse_note: str = ""


class LogAnalysis(BaseModel):
    analysis_id: str
    project_id: str = "unassigned"
    files: List[UploadedFile] = Field(default_factory=list)
    source_type: str = "Auto Detect"
    context: dict = Field(default_factory=dict)
    services: List[str] = Field(default_factory=list)
    time_start: str = ""
    time_end: str = ""
    record_count: int = 0
    error_codes: List[str] = Field(default_factory=list)
    warning_count: int = 0
    status: str = "parsed"
    created_at: str = ""
    rca: dict = Field(default_factory=dict)
