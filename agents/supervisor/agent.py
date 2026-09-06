"""
Supervisor Agent - controlled orchestration of specialized investigation agents.
Determines investigation plan, routing, missing evidence handling, and loop bounding.
"""
import logging
from typing import List
from datetime import datetime, timezone

from schemas.evidence import IncidentEvidence
from orchestration.state import InvestigationState
from .prompts import SUPERVISOR_SYSTEM_INSTRUCTION

logger = logging.getLogger("supervisor_agent")

# Canonical task names ordered as per spec
DEFAULT_PLAN_STEPS = [
    "Analyze application errors",
    "Compare baseline vs incident metrics",
    "Check recent deployments",
    "Inspect trace and dependency evidence",
    "Search historical incidents and runbooks",
    "Generate root-cause hypotheses",
    "Validate hypotheses",
    "Assess blast radius",
    "Generate final report",
]

# Mapping from plan step keyword -> agent
STEP_AGENT_MAP = {
    "application errors": "log_agent",
    "metrics": "metrics_agent",
    "deployments": "deployment_agent",
    "trace": "trace_agent",
    "dependency": "trace_agent",
    "historical": "knowledge_agent",
    "runbooks": "knowledge_agent",
}

MAX_INVESTIGATION_ROUNDS = 3


class SupervisorAgent:
    """Supervisor Agent implementation (deterministic + optional Gemini)."""

    def __init__(self, model_name: str = None):
        self.model_name = model_name
        self._client = None
        # Attempt Gemini init but fallback to deterministic
        try:
            import os
            from dotenv import load_dotenv
            load_dotenv()
            api_key = os.getenv("GEMINI_API_KEY")
            if api_key:
                from google import genai
                self._client = genai.Client(api_key=api_key)
        except Exception:
            self._client = None

    def create_plan(self, evidence: IncidentEvidence) -> List[str]:
        """
        Deterministic routing: select agents based on observable symptoms.
        Returns investigation plan (list of task strings).
        """
        plan = []
        symptoms_text = " ".join(evidence.symptoms).lower()
        has_app_errors = len(evidence.application_errors) > 0
        has_request_errors = len(evidence.request_errors) > 0
        has_deployments = len(evidence.recent_deployments) > 0
        has_traces = len(evidence.traces) > 0
        has_deps = len(evidence.dependencies) > 0
        latency_sev = evidence.latency.get("severity", "NORMAL") if isinstance(evidence.latency, dict) else "NORMAL"

        # Always needed
        if has_app_errors or has_request_errors:
            plan.append("Analyze application errors")
        else:
            # Even without explicit errors, logs may contain clues
            plan.append("Analyze application errors")

        plan.append("Compare baseline vs incident metrics")

        # Deployment check only if recent deployments exist or error suggests deployment
        if has_deployments:
            plan.append("Check recent deployments")
        else:
            # Still check if symptoms mention deployment/revision
            if "deploy" in symptoms_text or "revision" in symptoms_text:
                plan.append("Check recent deployments")

        if has_traces or has_deps:
            plan.append("Inspect trace and dependency evidence")

        plan.append("Search historical incidents and runbooks")
        plan.append("Generate root-cause hypotheses")
        plan.append("Validate hypotheses")
        plan.append("Assess blast radius")
        plan.append("Generate final report")
        return plan

    def initialize_state(self, evidence: IncidentEvidence) -> InvestigationState:
        plan = self.create_plan(evidence)
        state = InvestigationState(
            incident_id=evidence.incident_id,
            incident_evidence=evidence,
        )
        state.set_investigation_plan(plan)
        state.trace.started_at = datetime.now(timezone.utc).isoformat()
        logger.info(f"Supervisor created plan with {len(plan)} steps: {plan}")
        return state

    def decide_additional_tasks(self, state: InvestigationState) -> List[str]:
        """
        After Critic validation, decide if additional investigation needed.
        Returns new tasks or empty if no further investigation.
        """
        if state.investigation_round >= state.max_rounds:
            return []
        # Collect missing checks from validations
        pending = []
        for v in state.validated_hypotheses + state.rejected_hypotheses:
            for check in v.missing_checks + v.additional_investigation_required:
                if check not in pending:
                    pending.append(check)
        # Also from missing_evidence
        for m in state.missing_evidence:
            # Map missing evidence to concrete tasks
            if "pool" in m.lower() and "Investigate application connection pool saturation" not in pending:
                pending.append("Investigate application connection pool saturation")
            elif "database" in m.lower() and "Check database instance metrics" not in pending:
                pending.append("Check database instance metrics")
        return pending[:2]  # limit to 2 per round to avoid explosion

    def should_continue(self, state: InvestigationState) -> bool:
        # Continue if there are pending validations requiring more evidence
        needs_more = any(
            v.validation_status.value in ("INSUFFICIENT_EVIDENCE", "PARTIALLY_SUPPORTED")
            for v in state.validated_hypotheses + state.rejected_hypotheses
        )
        has_pending = len(state.pending_tasks) > 0
        return (needs_more or has_pending) and state.investigation_round < state.max_rounds
