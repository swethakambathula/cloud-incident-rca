"""
End-to-end demo: incident trigger -> investigate -> remediate -> verify -> store -> postmortem
Usage: python incident_demo.py --scenario bad-deployment --auto-investigate
Scenarios: bad-deployment, traffic-overload, dependency-outage
"""
import argparse, json, os, time
from schemas.evidence import IncidentEvidence
from orchestration.workflow import InvestigationWorkflow
from agents.remediation_agent.agent import RemediationAgent
from approval.manager import global_approval_manager
from agents.executor_agent.agent import ExecutorAgent
from agents.verification_agent.agent import VerificationAgent
from memory.store import MemoryStore
from memory.schemas import IncidentMemoryRecord
from memory.postmortem import generate_postmortem
from audit.logger import audit_log

SCENARIO_MAP = {
    "bad-deployment": "data/incidents/incident_003_bad_deployment.json",
    "traffic-overload": "data/incidents/incident_005_traffic_overload.json",
    "dependency-outage": "data/incidents/incident_004_dependency_outage.json",
    "db-timeout": "data/incidents/incident_001_db_timeout.json",
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default="bad-deployment", choices=list(SCENARIO_MAP.keys()))
    parser.add_argument("--auto-investigate", action="store_true")
    parser.add_argument("--auto-approve", action="store_true", help="Auto-approve for demo")
    args = parser.parse_args()

    path = SCENARIO_MAP[args.scenario]
    print(f"Incident Triggered: {args.scenario} -> {path}")
    with open(path) as f:
        data = json.load(f)
    ev = IncidentEvidence(**data)
    print(f"Evidence Collected: {ev.incident_id}")

    print("Investigation Started...")
    wf = InvestigationWorkflow()
    state = wf.run(ev, verbose=False)
    print(f"Multi-Agent RCA Completed: {state.hypotheses[0].root_cause_category} conf {state.hypotheses[0].confidence_score}")
    print(f"Critic Validated: {len(state.validated_hypotheses)} accepted, {len(state.rejected_hypotheses)} rejected")
    print(f"Blast Radius: {state.blast_radius.classification}")

    # Remediation planning
    rem_agent = RemediationAgent()
    cat = None
    if state.validated_hypotheses:
        best = max([v for v in state.validated_hypotheses if v.accepted], key=lambda x: x.adjusted_confidence, default=None)
        if best:
            hyp = next((h for h in state.hypotheses if h.hypothesis_id==best.hypothesis_id), None)
            if hyp:
                cat = hyp.root_cause_category
    plan = rem_agent.plan(ev, state.final_report, validated_category=cat)
    print(f"Remediation Proposed: {plan.recommended_action} risk {plan.estimated_risk.value} - {plan.expected_effect}")
    print(f"Rollback: {plan.rollback_plan}")

    # Approval
    approval = global_approval_manager.create_request(
        incident_id=ev.incident_id, action=plan.recommended_action, target_resource=plan.target_resource,
        rationale=plan.expected_effect, root_cause=plan.root_cause, confidence=plan.confidence, risk=plan.estimated_risk.value,
        expected_impact=plan.expected_effect, rollback_plan=plan.rollback_plan
    )
    audit_log("REMEDIATION_PLANNED", ev.incident_id, "RemediationAgent", plan.recommended_action, approval.target_resource, approval_id=approval.approval_id)
    print(f"Approval Pending: {approval.approval_id} - POST /approvals/{approval.approval_id}/approve to approve")

    if args.auto_approve:
        print("Auto-approving for demo...")
        global_approval_manager.approve(approval.approval_id, approver="demo-auto")
        approval = global_approval_manager.get(approval.approval_id)
        print(f"Approved: {approval.status}")

        # Execute - prepare action params per scenario
        params = {}
        if plan.recommended_action == "cloud_run_rollback":
            # find previous revision
            if len(ev.recent_deployments) >=2:
                params = {"target_revision": ev.recent_deployments[1].get("revision_name")}
            else:
                params = {"target_revision": f"{ev.service_name}-00004-v1"}
        elif plan.recommended_action == "cloud_run_scale_within_limits":
            params = {"max_instances": 10}
        elif plan.recommended_action == "cloud_run_shift_traffic":
            params = {"revision_percentages": {ev.revision_name: 100}}

        executor = ExecutorAgent()
        result = executor.execute(approval, params)
        print(f"Action Executed: {result.status} op {result.cloud_operation_id}")
        audit_log("EXECUTION", ev.incident_id, "ExecutorAgent", approval.action, approval.target_resource, before=result.before_state, after=result.after_state, approval_id=approval.approval_id)

        # Verification
        print("Verification Started...")
        verifier = VerificationAgent()
        metrics_before = {"error_rate_pct": 30, "latency_p95_ms": 3000}
        metrics_after = {"error_rate_pct": 0.5 if result.status.value=="SUCCESS" else 25, "latency_p95_ms": 180 if result.status.value=="SUCCESS" else 2800}
        verification = verifier.verify(ev.incident_id, result, metrics_before, metrics_after)
        print(f"Verification: {verification.verification_status} - {verification.summary}")

        # Storage
        store = MemoryStore()
        rec = IncidentMemoryRecord(
            incident_id=ev.incident_id, service=ev.service_name, symptoms=ev.symptoms,
            timeline=[{"timestamp": t.timestamp, "description": t.description} for t in state.final_report.timeline],
            root_cause=state.final_report.root_cause, root_cause_category=cat or "unknown",
            supporting_evidence=state.final_report.supporting_evidence, rejected_hypotheses=[h.root_cause_category for h in state.hypotheses if h.root_cause_category!=cat],
            blast_radius=state.blast_radius.model_dump(), remediation=plan.model_dump(), approval_outcome=approval.status.value,
            execution_result=result.model_dump(), verification_result=verification.model_dump(),
            final_status=verification.verification_status.value, timestamps={}, confidence=state.final_report.confidence
        )
        store.save(rec)
        pm = generate_postmortem(rec)
        print(f"Incident Stored: {ev.incident_id}")
        print(f"Postmortem Generated: {pm['incident_summary']}")
        print("Demo flow complete: DETECTED -> INVESTIGATING -> RCA_VALIDATED -> REMEDIATION_PLANNED -> APPROVED -> REMEDIATING -> VERIFYING -> RESOLVED")
    else:
        print("Awaiting human approval. Approve via: curl -X POST http://localhost:8080/approvals/{id}/approve")

if __name__ == "__main__":
    main()
