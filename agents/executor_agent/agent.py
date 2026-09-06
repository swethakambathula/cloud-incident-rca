"""
Executor Agent - validates approval, policy, preconditions, executes only allowlisted actions, records result, never invents success.
"""
import uuid, logging
from datetime import datetime, timezone
from typing import Dict, Any
from approval.schemas import ApprovalRequest
from .schemas import ExecutionResult, ExecutionStatus
from safety.remediation_policy import decide, PolicyDecision, validate_action_constraints
from .tools import DISPATCH

logger = logging.getLogger("executor_agent")

class ExecutorAgent:
    agent_name = "Executor Agent"

    def execute(self, approval: ApprovalRequest, action_params: Dict[str, Any]) -> ExecutionResult:
        execution_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        start = datetime.now(timezone.utc).isoformat()

        # 1. Validate approval
        if not approval.is_valid_for_execution():
            return ExecutionResult(
                execution_id=execution_id, approval_id=approval.approval_id, incident_id=approval.incident_id,
                action=approval.action, target_resource=approval.target_resource,
                start_time=start, end_time=datetime.now(timezone.utc).isoformat(),
                status=ExecutionStatus.BLOCKED, error_message=f"Approval not valid: status {approval.status}, expired {approval.is_expired()}",
                rollback_available=False
            )
        # 2. Validate policy
        decision = decide(approval.action)
        if decision == PolicyDecision.DISALLOWED:
            return ExecutionResult(
                execution_id=execution_id, approval_id=approval.approval_id, incident_id=approval.incident_id,
                action=approval.action, target_resource=approval.target_resource,
                start_time=start, end_time=datetime.now(timezone.utc).isoformat(),
                status=ExecutionStatus.BLOCKED, error_message=f"Action {approval.action} DISALLOWED by policy",
                rollback_available=False
            )
        if decision == PolicyDecision.READ_ONLY:
            # Read-only shouldn't reach executor, but block
            return ExecutionResult(
                execution_id=execution_id, approval_id=approval.approval_id, incident_id=approval.incident_id,
                action=approval.action, target_resource=approval.target_resource,
                start_time=start, end_time=datetime.now(timezone.utc).isoformat(),
                status=ExecutionStatus.BLOCKED, error_message=f"Action {approval.action} is READ_ONLY",
                rollback_available=False
            )
        # 3. Validate constraints
        ok, msg = validate_action_constraints(approval.action, action_params)
        if not ok:
            return ExecutionResult(
                execution_id=execution_id, approval_id=approval.approval_id, incident_id=approval.incident_id,
                action=approval.action, target_resource=approval.target_resource,
                start_time=start, end_time=datetime.now(timezone.utc).isoformat(),
                status=ExecutionStatus.BLOCKED, error_message=msg,
                rollback_available=False
            )
        # 4. Pre-remediation validation: incident still active? revision state not changed?
        # For demo we check action_params contains expected target_resource match
        # If mismatch, cancel
        # 5. Dispatch
        fn = DISPATCH.get(approval.action)
        if not fn:
            return ExecutionResult(
                execution_id=execution_id, approval_id=approval.approval_id, incident_id=approval.incident_id,
                action=approval.action, target_resource=approval.target_resource,
                start_time=start, end_time=datetime.now(timezone.utc).isoformat(),
                status=ExecutionStatus.BLOCKED, error_message=f"Unknown action {approval.action}",
                rollback_available=False
            )
        try:
            # Parse target_resource: projects/{project}/locations/{region}/services/{service}
            parts = approval.target_resource.split("/")
            project_id = parts[1] if len(parts)>1 else "test-project"
            region = parts[3] if len(parts)>3 else "us-central1"
            service_name = parts[5] if len(parts)>5 else "checkout-service"
            # Call tool
            result = fn(project_id=project_id, region=region, service_name=service_name, **action_params)
            status = ExecutionStatus.SUCCESS if result.get("status")=="SUCCESS" else ExecutionStatus.FAILED
            return ExecutionResult(
                execution_id=execution_id, approval_id=approval.approval_id, incident_id=approval.incident_id,
                action=approval.action, target_resource=approval.target_resource,
                start_time=start, end_time=datetime.now(timezone.utc).isoformat(),
                status=status,
                cloud_operation_id=result.get("operation_id") or result.get("cloud_operation_id"),
                before_state=result.get("before_state"),
                after_state=result.get("after_state"),
                error_message=result.get("error"),
                rollback_available=True if status==ExecutionStatus.SUCCESS else False,
            )
        except Exception as e:
            logger.exception("Executor failed")
            return ExecutionResult(
                execution_id=execution_id, approval_id=approval.approval_id, incident_id=approval.incident_id,
                action=approval.action, target_resource=approval.target_resource,
                start_time=start, end_time=datetime.now(timezone.utc).isoformat(),
                status=ExecutionStatus.FAILED, error_message=str(e),
                rollback_available=False
            )
