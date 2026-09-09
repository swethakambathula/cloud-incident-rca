"""
Approval Manager - deterministic gating for remediation.
"""
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional
from .schemas import ApprovalRequest, ApprovalStatus
import logging

logger = logging.getLogger("approval_manager")

class ApprovalManager:
    def __init__(self):
        self._store: Dict[str, ApprovalRequest] = {}

    def create_request(self, incident_id: str, action: str, target_resource: str, rationale: str,
                       root_cause: str, confidence: float, risk: str, expected_impact: str,
                       rollback_plan: str, expiration_minutes: int = 60,
                       action_type: str = "INFRASTRUCTURE_ACTION",
                       patch_sha256: Optional[str] = None) -> ApprovalRequest:
        approval_id = f"APPROVAL-{uuid.uuid4().hex[:8].upper()}"
        exp = (datetime.now(timezone.utc) + timedelta(minutes=expiration_minutes)).isoformat()
        req = ApprovalRequest(
            approval_id=approval_id,
            incident_id=incident_id,
            action=action,
            target_resource=target_resource,
            rationale=rationale,
            root_cause=root_cause,
            confidence=confidence,
            risk=risk,
            expected_impact=expected_impact,
            rollback_plan=rollback_plan,
            expiration_time=exp,
            status=ApprovalStatus.PENDING,
            action_type=action_type,
            patch_sha256=patch_sha256,
        )
        self._store[approval_id] = req
        logger.info(f"Created approval {approval_id} for {action} PENDING")
        return req

    def get(self, approval_id: str) -> Optional[ApprovalRequest]:
        req = self._store.get(approval_id)
        if req and req.status == ApprovalStatus.PENDING and req.is_expired():
            req.status = ApprovalStatus.EXPIRED
        return req

    def approve(self, approval_id: str, approver: str = "human-operator", message: Optional[str] = None) -> Optional[ApprovalRequest]:
        req = self.get(approval_id)
        if not req:
            return None
        if req.status != ApprovalStatus.PENDING:
            return req
        req.status = ApprovalStatus.APPROVED
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = approver
        req.decided_message = (message or "").strip() or None
        logger.info(f"Approved {approval_id} by {approver}: {req.decided_message}")
        return req

    def reject(self, approval_id: str, approver: str = "human-operator", message: Optional[str] = None) -> Optional[ApprovalRequest]:
        req = self.get(approval_id)
        if not req:
            return None
        if req.status != ApprovalStatus.PENDING:
            return req
        req.status = ApprovalStatus.REJECTED
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = approver
        req.decided_message = (message or "").strip() or None
        logger.info(f"Rejected {approval_id} by {approver}: {req.decided_message}")
        return req

    def cancel(self, approval_id: str) -> Optional[ApprovalRequest]:
        req = self.get(approval_id)
        if not req:
            return None
        if req.status == ApprovalStatus.PENDING:
            req.status = ApprovalStatus.CANCELLED
            req.decided_at = datetime.now(timezone.utc).isoformat()
        return req

    def list_pending(self):
        return [r for r in self._store.values() if r.status == ApprovalStatus.PENDING]

    def list_recent(self, limit: int = 10):
        """Decided approvals (approved/rejected/expired/cancelled), newest first — decision history."""
        decided = [r for r in self._store.values() if r.status != ApprovalStatus.PENDING]
        decided.sort(key=lambda r: r.decided_at or r.requested_at or "", reverse=True)
        return decided[:limit]

# Global singleton for demo
global_approval_manager = ApprovalManager()
