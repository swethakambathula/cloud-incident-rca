"""
Incident State Machine - valid transitions only.
"""
from typing import Dict, Set
from enum import Enum

class IncidentState(str, Enum):
    DETECTED = "DETECTED"
    INVESTIGATING = "INVESTIGATING"
    RCA_GENERATED = "RCA_GENERATED"
    RCA_VALIDATED = "RCA_VALIDATED"
    REMEDIATION_PLANNED = "REMEDIATION_PLANNED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    REMEDIATING = "REMEDIATING"
    VERIFYING = "VERIFYING"
    RESOLVED = "RESOLVED"
    FAILED = "FAILED"
    ESCALATED = "ESCALATED"

VALID_TRANSITIONS: Dict[IncidentState, Set[IncidentState]] = {
    IncidentState.DETECTED: {IncidentState.INVESTIGATING},
    IncidentState.INVESTIGATING: {IncidentState.RCA_GENERATED, IncidentState.FAILED, IncidentState.ESCALATED},
    IncidentState.RCA_GENERATED: {IncidentState.RCA_VALIDATED, IncidentState.FAILED},
    IncidentState.RCA_VALIDATED: {IncidentState.REMEDIATION_PLANNED, IncidentState.FAILED, IncidentState.ESCALATED},
    IncidentState.REMEDIATION_PLANNED: {IncidentState.APPROVAL_PENDING, IncidentState.FAILED},
    IncidentState.APPROVAL_PENDING: {IncidentState.APPROVED, IncidentState.FAILED, IncidentState.ESCALATED},  # REJECTED goes to FAILED/ESCALATED
    IncidentState.APPROVED: {IncidentState.REMEDIATING, IncidentState.FAILED},
    IncidentState.REMEDIATING: {IncidentState.VERIFYING, IncidentState.FAILED},
    IncidentState.VERIFYING: {IncidentState.RESOLVED, IncidentState.FAILED, IncidentState.ESCALATED},  # PARTIALLY -> FAILED for demo, REGRESSED -> FAILED requiring rollback approval
    IncidentState.RESOLVED: set(),
    IncidentState.FAILED: {IncidentState.ESCALATED},
    IncidentState.ESCALATED: set(),
}

class IncidentStateMachine:
    def __init__(self, initial: IncidentState = IncidentState.DETECTED):
        self.state = initial
        self.history = [initial.value]

    def transition(self, target: IncidentState) -> bool:
        if target in VALID_TRANSITIONS.get(self.state, set()):
            self.state = target
            self.history.append(target.value)
            return True
        raise ValueError(f"Invalid transition {self.state.value} -> {target.value}. Allowed: {VALID_TRANSITIONS.get(self.state)}")

    def can_transition(self, target: IncidentState) -> bool:
        return target in VALID_TRANSITIONS.get(self.state, set())
