"""
ApprovalRequest schemas
"""
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum
from datetime import datetime, timezone, timedelta

class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"

class ApprovalRequest(BaseModel):
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
    expiration_time: str  # ISO8601
    requested_by_agent: str = "RemediationAgent"
    status: ApprovalStatus = ApprovalStatus.PENDING
    action_type: str = "INFRASTRUCTURE_ACTION"
    patch_sha256: Optional[str] = Field(default=None, description="Exact patch hash this approval binds to (CODE_CHANGE only)")
    requested_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decided_message: Optional[str] = Field(default=None, description="Custom approver message/reason sent with approve/reject")

    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expiration_time.replace("Z","+00:00"))
            return datetime.now(timezone.utc) > exp
        except:
            return False

    def is_valid_for_execution(self) -> bool:
        return self.status == ApprovalStatus.APPROVED and not self.is_expired()
