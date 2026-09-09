"""
Code fix schemas (Parts 5-8): investigation findings, patch proposals, fix jobs.
"""
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class CodeFinding(BaseModel):
    file: str
    start_line: int
    end_line: int
    snippet: str
    reason: str
    current_value: Optional[str] = None
    related_test: Optional[str] = None


class CodeInvestigation(BaseModel):
    incident_id: str
    root_cause_category: str
    repo: str = "cloud-rca-demo-app"
    findings: List[CodeFinding] = Field(default_factory=list)
    no_fix_reason: Optional[str] = None


class PatchProposal(BaseModel):
    incident_id: str
    root_cause_category: str
    files_changed: List[str] = Field(default_factory=list)
    summary: str
    risk: str = "LOW"
    patch: str = Field(description="Unified diff text")
    tests_to_run: List[str] = Field(default_factory=list)
    reasoning_summary: str
    patch_sha256: str
    lines_added: int = 0
    lines_removed: int = 0


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


class FixJob(BaseModel):
    incident_id: str
    status: FixStatus = FixStatus.SUGGESTED
    root_cause_category: str = ""
    branch: Optional[str] = None
    commit: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    patch_sha256: Optional[str] = None
    approval_id: Optional[str] = None
    test_output: Optional[str] = None
    error: Optional[str] = None
