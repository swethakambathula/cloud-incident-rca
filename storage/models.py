"""
SQLite storage models for Cloud Incident RCA Agent.
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
    NEW = "NEW"
    COLLECTING_EVIDENCE = "COLLECTING_EVIDENCE"
    ANALYZING = "ANALYZING"
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    APPROVED = "APPROVED"
    PR_CREATING = "PR_CREATING"
    PR_CREATED = "PR_CREATED"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"


class IncidentSource(str, Enum):
    MANUAL = "MANUAL"
    SIMULATION = "SIMULATION"
    LOG_UPLOAD = "LOG_UPLOAD"


class RCAStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class ActionType(str, Enum):
    INFRASTRUCTURE_ACTION = "INFRASTRUCTURE_ACTION"
    CODE_CHANGE = "CODE_CHANGE"


class FixStatus(str, Enum):
    SUGGESTED = "Suggested"
    WAITING_FOR_APPROVAL = "Waiting for Approval"
    APPROVED = "Approved"
    BRANCH_CREATED = "Branch Created"
    PATCH_APPLIED = "Patch Applied"
    TESTING = "Testing"
    TESTS_PASSED = "Tests Passed"
    COMMITTED = "Committed"
    PUSHED = "Pushed"
    PR_CREATED = "PR Created"
    REJECTED = "Rejected"
    FAILED = "Failed"


class PRStatus(str, Enum):
    OPEN = "Open"
    MERGED = "Merged"
    CLOSED = "Closed"
    DRAFT = "Draft"
    FAILED = "Failed"
    AWAITING_APPROVAL = "Awaiting Approval"


class VerificationStatus(str, Enum):
    RESOLVED = "RESOLVED"
    REGRESSED = "REGRESSED"
    INCONCLUSIVE = "INCONCLUSIVE"
    PENDING = "PENDING"


class ProjectModel(BaseModel):
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
    region: str = "us-central1"
    services_json: str = "[]"
    service_mappings_json: str = "{}"
    readiness_json: str = "{}"
    status: str = "active"
    created_at: str
    last_scan: str = ""
    detected_json: str = "{}"
    data_sources_json: str = "[]"
    repo_access: str = "READ_ONLY"
    demo_mode: bool = False


class IncidentModel(BaseModel):
    id: str
    project_id: str = "unassigned"
    title: str
    description: str = ""
    severity: str = "P2"
    status: str = "NEW"
    source: str = "MANUAL"
    evidence_source: str = "manual"
    scenario_id: str = ""
    is_simulation: bool = False
    affected_services_json: str = "[]"
    started_at: str
    created_at: str
    updated_at: str
    resolved_at: str = ""
    resolution_reason: str = ""
    error_domain: str = ""
    error_subcategory: str = ""
    pr_id: str = ""


class RCARunModel(BaseModel):
    id: str
    incident_id: str
    analysis_session_id: str = ""
    status: str = "PENDING"
    root_cause_code: str = ""
    root_cause_summary: str = ""
    confidence: float = 0.0
    quality_score: float = 0.0
    requires_remediation: int = 0
    requires_code_fix: int = 0
    requires_approval: int = 0
    requires_pr: int = 0
    result_json: str = "{}"
    created_at: str
    started_at: str = ""
    completed_at: str = ""
    error: str = ""


class AnalysisSessionModel(BaseModel):
    session_id: str
    project_id: str
    analysis_ids_json: str = "[]"
    context_json: str = "{}"
    converted_incident_id: str = ""
    created_at: str


class CodeFixModel(BaseModel):
    id: str
    incident_id: str
    rca_run_id: str = ""
    project_id: str = ""
    repository: str = "cloud-rca-demo-app"
    base_branch: str = "main"
    proposed_branch: str = ""
    status: str = "SUGGESTED"
    title: str = ""
    summary: str = ""
    reason: str = ""
    risk: str = "LOW"
    fix_confidence: float = 0.0
    patch_sha256: str = ""
    diff_text: str = ""
    files_json: str = "[]"
    tests_json: str = "[]"
    test_result_json: str = "{}"
    created_at: str
    updated_at: str


class FixJobModel(BaseModel):
    id: str
    incident_id: str
    status: str = "SUGGESTED"
    root_cause_category: str = ""
    branch: str = ""
    commit_sha: str = ""
    pr_number: int = 0
    pr_url: str = ""
    patch_sha256: str = ""
    approval_id: str = ""
    test_output: str = ""
    error: str = ""
    created_at: str
    updated_at: str


class ApprovalModel(BaseModel):
    approval_id: str
    incident_id: str
    action: str
    target_resource: str
    rationale: str
    root_cause: str
    confidence: float
    risk: str
    expected_impact: str
    rollback_plan: str
    expiration_time: str
    status: str = "PENDING"
    action_type: str = "INFRASTRUCTURE_ACTION"
    patch_sha256: str = ""
    decided_at: str = ""
    decided_by: str = ""
    decided_message: str = ""
    requested_at: str
    execution_status: str = ""
    execution_result_json: str = "{}"


from typing import Optional

class PullRequestModel(BaseModel):
    id: str
    provider: str = "github"
    project_id: str = ""
    incident_id: str = ""
    rca_run_id: Optional[str] = None
    code_fix_id: Optional[str] = None
    fix_job_id: Optional[str] = None
    repository: str = ""
    pr_number: int = 0
    title: str = ""
    url: str = ""
    source_branch: str = ""
    target_branch: str = ""
    status: str = "OPEN"
    checks_state: str = ""
    created_at: str
    updated_at: str
    merged_at: Optional[str] = None
    closed_at: Optional[str] = None
    merge_commit_sha: Optional[str] = None
    provider_payload_json: str = "{}"
    root_cause: str = ""
    root_cause_category: str = ""
    confidence: float = 0.0
    risk: str = ""
    tests_status: str = ""
    tests_output: str = ""
    files_changed_json: str = "[]"
    additions: int = 0
    deletions: int = 0
    diff: str = ""
    approval_id: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    external_url: Optional[str] = None


class VerificationResultModel(BaseModel):
    id: str
    incident_id: str
    execution_id: str = ""
    verification_status: str = "PENDING"
    summary: str = ""
    error_rate_before: float = 0.0
    error_rate_after: float = 0.0
    latency_before: float = 0.0
    latency_after: float = 0.0
    metrics_before_json: str = "{}"
    metrics_after_json: str = "{}"
    resolution_checks_json: str = "[]"
    created_at: str


class ActivityEventModel(BaseModel):
    id: str
    timestamp: str
    actor: str
    event: str
    incident_id: str = ""
    description: str = ""
    metadata_json: str = "{}"


class IncidentMemoryModel(BaseModel):
    id: str
    incident_id: str
    service: str = ""
    symptoms_json: str = "[]"
    timeline_json: str = "[]"
    root_cause: str = ""
    root_cause_category: str = ""
    supporting_evidence_json: str = "[]"
    blast_radius_json: str = "{}"
    remediation_json: str = "{}"
    approval_outcome: str = ""
    execution_result_json: str = "{}"
    verification_result_json: str = "{}"
    final_status: str = ""
    timestamps_json: str = "{}"
    confidence: float = 0.0
    code_paths_json: str = "[]"
    error_signatures_json: str = "[]"
    resolution_json: str = "{}"
    pr_id: str = ""
    verification_outcome: str = ""
    created_at: str


class SchemaVersionModel(BaseModel):
    version: int
    applied_at: str
    description: str = ""


class IdempotencyKeyModel(BaseModel):
    key: str
    entity_type: str
    entity_id: str
    created_at: str
    expires_at: str