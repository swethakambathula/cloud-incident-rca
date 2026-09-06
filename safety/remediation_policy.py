"""
Safety Remediation Policy Engine - deterministic, LLM cannot bypass.
Decides READ_ONLY / ALLOWED_WITH_APPROVAL / DISALLOWED
"""
from enum import Enum
from typing import Dict

class PolicyDecision(str, Enum):
    READ_ONLY = "READ_ONLY"
    ALLOWED_WITH_APPROVAL = "ALLOWED_WITH_APPROVAL"
    DISALLOWED = "DISALLOWED"

# Deterministic allowlist
ALLOWED_ACTIONS = {
    "cloud_run_rollback": {
        "resource_type": "cloud_run_service",
        "max_change": "traffic 100% shift to previous revision",
        "requires_approval": True,
        "rollback": "shift traffic back",
    },
    "cloud_run_shift_traffic": {
        "resource_type": "cloud_run_service",
        "max_change": "percentages must total 100",
        "requires_approval": True,
        "rollback": "previous traffic split",
    },
    "cloud_run_scale_within_limits": {
        "resource_type": "cloud_run_service",
        "max_change": "bounded limits (MAX_SCALE_LIMIT env)",
        "requires_approval": True,
        "rollback": "restore previous min/max",
    },
    # Read-only actions never need approval but also never mutate
    "inspect_service": {"resource_type": "cloud_run_service", "requires_approval": False},
    "inspect_revision": {"resource_type": "cloud_run_revision", "requires_approval": False},
    "inspect_traffic_split": {"resource_type": "cloud_run_service", "requires_approval": False},
    "inspect_logs": {"resource_type": "cloud_logging", "requires_approval": False},
    "inspect_metrics": {"resource_type": "cloud_monitoring", "requires_approval": False},
}

DISALLOWED_ACTIONS = {
    "delete_project", "delete_database", "delete_bucket", "alter_organization_policies",
    "grant_owner_role", "remove_audit_logging", "disable_monitoring",
    "arbitrary_shell_execution", "arbitrary_iam_modification", "destructive_data_mutation",
    "delete_service", "delete_revision",
}

READ_ONLY_ACTIONS = {"inspect_service", "inspect_revision", "inspect_traffic_split", "inspect_logs", "inspect_metrics"}

def decide(action: str) -> PolicyDecision:
    if action in DISALLOWED_ACTIONS:
        return PolicyDecision.DISALLOWED
    if action in READ_ONLY_ACTIONS:
        return PolicyDecision.READ_ONLY
    if action in ALLOWED_ACTIONS:
        entry = ALLOWED_ACTIONS[action]
        if entry.get("requires_approval"):
            return PolicyDecision.ALLOWED_WITH_APPROVAL
        return PolicyDecision.READ_ONLY
    # Unknown actions are DISALLOWED by default - prevents LLM inventing actions
    return PolicyDecision.DISALLOWED

def validate_action_constraints(action: str, params: Dict) -> (bool, str):
    """Check guardrails for allowlisted actions"""
    if action == "cloud_run_shift_traffic":
        perc = params.get("revision_percentages", {})
        if not perc:
            return False, "Missing revision_percentages"
        if sum(perc.values()) != 100:
            return False, f"Percentages must total 100, got {sum(perc.values())}"
        if any(v < 0 or v > 100 for v in perc.values()):
            return False, "Invalid percentage values"
    if action == "cloud_run_scale_within_limits":
        import os
        max_limit = int(os.getenv("MAX_SCALE_LIMIT", "20"))
        max_instances = params.get("max_instances")
        if max_instances is not None and max_instances > max_limit:
            return False, f"max_instances {max_instances} exceeds MAX_SCALE_LIMIT {max_limit}"
        if max_instances == 0 and params.get("min_instances", 1) == 0:
            return False, "Zeroing production service requires explicit approval flag not set"
    if action == "cloud_run_rollback":
        target = params.get("target_revision")
        if not target:
            return False, "target_revision required"
        # further validation done in tool (exists, older)
        pass
    return True, "ok"

def is_allowed(action: str) -> bool:
    return decide(action) != PolicyDecision.DISALLOWED
