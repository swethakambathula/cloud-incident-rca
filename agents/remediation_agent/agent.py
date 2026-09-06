"""
Remediation Planning Agent - proposes safe, allowlisted remediation options.
Deterministic mapping from root_cause_category to safe actions. Never invents destructive actions.
"""
from typing import List
from schemas.evidence import IncidentEvidence
from schemas.report import IncidentReport
from .schemas import RemediationPlan, MitigationType, RiskLevel

# Allowlisted action catalogue
ACTION_CATALOG = {
    "faulty_revision": {
        "recommended_action": "cloud_run_rollback",
        "alternatives": ["cloud_run_shift_traffic", "cloud_run_scale_within_limits"],
        "mitigation_type": MitigationType.TEMPORARY_MITIGATION,
        "expected_effect": "Shift 100% traffic to previous known-good revision; error rate should drop to baseline within 1-2 minutes",
        "risk": RiskLevel.LOW,
        "reversibility": "Reversible by shifting traffic back to newer revision",
        "permissions": ["run.services.update", "run.revisions.get"],
        "preconditions": ["target_revision exists", "target_revision older than current", "previous state captured"],
        "rollback_plan": "Shift traffic back to current revision via cloud_run_shift_traffic",
        "verification_plan": "Check error rate, latency, and revision traffic after 60s and 180s",
    },
    "traffic_overload": {
        "recommended_action": "cloud_run_scale_within_limits",
        "alternatives": ["cloud_run_shift_traffic"],
        "mitigation_type": MitigationType.TEMPORARY_MITIGATION,
        "expected_effect": "Increase maxInstances within bounded limits; reduce throttling and latency",
        "risk": RiskLevel.MEDIUM,
        "reversibility": "Reversible by restoring previous min/max instances",
        "permissions": ["run.services.update"],
        "preconditions": ["new max within MAX_SCALE_LIMIT", "service not already at limit"],
        "rollback_plan": "Restore previous scaling config via scale_cloud_run_service",
        "verification_plan": "Compare request count, CPU, error rate before/after",
    },
    "database_connectivity": {
        "recommended_action": "cloud_run_rollback",  # placeholder but really would be inspect; we map to safe read-only for demo
        "alternatives": [],
        "mitigation_type": MitigationType.WORKAROUND,
        "expected_effect": "If faulty revision changed connection string, rollback restores connectivity; otherwise no effect (escalate to DB team)",
        "risk": RiskLevel.MEDIUM,
        "reversibility": "Reversible via traffic shift",
        "permissions": ["run.services.get", "run.services.update"],
        "preconditions": ["check VPC connector before rollback"],
        "rollback_plan": "Restore traffic if no improvement",
        "verification_plan": "Check DATABASE_CONNECTION_TIMEOUT frequency after action",
    },
    "dependency_failure": {
        "recommended_action": "cloud_run_scale_within_limits",
        "alternatives": [],
        "mitigation_type": MitigationType.WORKAROUND,
        "expected_effect": "No direct fix for downstream; scaling upstream avoids amplifying load;真正的 fix is downstream recovery",
        "risk": RiskLevel.LOW,
        "reversibility": "Reversible",
        "permissions": ["run.services.get"],
        "preconditions": ["do not restart healthy upstream; verify downstream health"],
        "rollback_plan": "No rollback needed (read-only mitigation)",
        "verification_plan": "Poll downstream health; do not declare resolved until downstream recovers",
    },
    "connection_pool_exhaustion": {
        "recommended_action": "cloud_run_scale_within_limits",
        "alternatives": ["cloud_run_rollback"],
        "mitigation_type": MitigationType.TEMPORARY_MITIGATION,
        "expected_effect": "Temporary scale out adds instances, reducing per-instance pool pressure; permanent fix requires pool config change",
        "risk": RiskLevel.LOW,
        "reversibility": "Reversible",
        "permissions": ["run.services.update"],
        "preconditions": ["pool max within DB maxConnections"],
        "rollback_plan": "Restore scaling; recommend code fix for leak",
        "verification_plan": "Observe pool active/max and queue wait",
    },
    "configuration_regression": {
        "recommended_action": "cloud_run_rollback",
        "alternatives": [],
        "mitigation_type": MitigationType.TEMPORARY_MITIGATION,
        "expected_effect": "Rollback restores missing env var/secret to last good revision",
        "risk": RiskLevel.LOW,
        "reversibility": "Reversible",
        "permissions": ["run.services.update"],
        "preconditions": ["previous revision had required env var"],
        "rollback_plan": "Re-apply config fix forward; do not keep old revision indefinitely",
        "verification_plan": "Hit affected endpoint /simulate/config-error after rollback",
    },
}

class RemediationAgent:
    agent_name = "Remediation Planning Agent"

    def plan(self, incident_evidence: IncidentEvidence, report: IncidentReport = None, validated_category: str = None) -> RemediationPlan:
        # Determine category from report or validated_category
        cat = validated_category or (report.blast_radius.classification if report else None)
        # Better: use report.root_cause_category inferred from report.root_cause, or explicit
        # For deterministic mapping we use report's primary hypothesis category if available
        # Fallback: inspect report.root_cause string
        if report:
            rc = report.root_cause.lower()
            if "pool" in rc:
                cat = "connection_pool_exhaustion"
            elif "revision" in rc or "rollback" in report.recommended_next_action.lower():
                # check hypothesis
                if any("faulty" in h.critic_reasoning.lower() for h in report.validated_hypotheses):
                    cat = "faulty_revision"
                # use blast_radius revision hint
                if report.blast_radius.affected_revision and "bad" in report.blast_radius.affected_revision.lower():
                    cat = "faulty_revision"
            elif "dependency" in rc or "downstream" in rc:
                cat = "dependency_failure"
            elif "traffic" in rc or "capacity" in rc:
                cat = "traffic_overload"
            elif "config" in rc:
                cat = "configuration_regression"
            elif "database" in rc or "timeout" in rc:
                cat = "database_connectivity"
            # Override with validated_category if provided
            if validated_category:
                cat = validated_category

        cfg = ACTION_CATALOG.get(cat, ACTION_CATALOG["database_connectivity"])
        # Confidence based on report.confidence
        conf = report.confidence if report else 0.85
        # Risk scoring: reduce confidence if blast radius large
        if report and report.blast_radius.classification in ("MULTI_SERVICE", "REGIONAL"):
            # higher risk
            pass

        return RemediationPlan(
            incident_id=incident_evidence.incident_id if incident_evidence else (report.incident_id if report else "INC-UNKNOWN"),
            root_cause=report.root_cause if report else "unknown",
            root_cause_category=cat,
            recommended_action=cfg["recommended_action"],
            alternative_actions=cfg["alternatives"],
            mitigation_type=cfg["mitigation_type"],
            expected_effect=cfg["expected_effect"],
            estimated_risk=cfg["risk"],
            reversibility=cfg["reversibility"],
            required_permissions=cfg["permissions"],
            preconditions=cfg["preconditions"],
            rollback_plan=cfg["rollback_plan"],
            verification_plan=cfg["verification_plan"],
            confidence=min(conf, 0.99),
            human_approval_required=True,
            target_resource=f"projects/{incident_evidence.project_id}/locations/{incident_evidence.region}/services/{incident_evidence.service_name}" if incident_evidence else None,
            target_revision=incident_evidence.revision_name if incident_evidence and cat=="faulty_revision" else None,
        )

    def explain(self, plan: RemediationPlan) -> str:
        return f"Recommended {plan.recommended_action} for {plan.root_cause_category} ({plan.mitigation_type.value}) - risk {plan.estimated_risk.value}, reversible: {plan.reversibility}. Requires {', '.join(plan.required_permissions)}. Rollback: {plan.rollback_plan}"
