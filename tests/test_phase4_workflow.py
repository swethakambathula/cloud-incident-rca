"""
Phase 4 end-to-end workflow tests
"""
import json, os
from schemas.evidence import IncidentEvidence
from orchestration.workflow import InvestigationWorkflow
from agents.remediation_agent.agent import RemediationAgent
from approval.manager import ApprovalManager
from agents.executor_agent.agent import ExecutorAgent
from agents.verification_agent.agent import VerificationAgent
from orchestration.incident_state_machine import IncidentStateMachine, IncidentState
from memory.store import MemoryStore
from memory.retrieval import find_similar_incidents

def test_remediation_rollback_scenario():
    path = "data/incidents/incident_003_bad_deployment.json"
    with open(path) as f:
        ev = IncidentEvidence(**json.load(f))
    wf = InvestigationWorkflow()
    state = wf.run(ev)
    # RCA should identify faulty_revision
    cat = next((h.root_cause_category for h in state.hypotheses if h.confidence_score==max(h.confidence_score for h in state.hypotheses)), None)
    assert cat == "faulty_revision"
    # Plan
    rem = RemediationAgent()
    plan = rem.plan(ev, state.final_report, validated_category=cat)
    assert plan.recommended_action == "cloud_run_rollback"
    assert plan.human_approval_required is True
    assert plan.estimated_risk.value in ("LOW","MEDIUM")
    # Approval
    mgr = ApprovalManager()
    appr = mgr.create_request(incident_id=ev.incident_id, action=plan.recommended_action, target_resource=plan.target_resource,
                              rationale=plan.expected_effect, root_cause=plan.root_cause, confidence=plan.confidence, risk=plan.estimated_risk.value,
                              expected_impact=plan.expected_effect, rollback_plan=plan.rollback_plan)
    assert appr.status.value == "PENDING"
    mgr.approve(appr.approval_id)
    assert mgr.get(appr.approval_id).status.value == "APPROVED"
    # Execute
    executor = ExecutorAgent()
    # Use previous revision
    target_rev = ev.recent_deployments[1].get("revision_name") if len(ev.recent_deployments)>=2 else "checkout-service-00004-v1"
    result = executor.execute(mgr.get(appr.approval_id), {"target_revision": target_rev})
    assert result.status.value == "SUCCESS"
    assert result.before_state is not None
    assert result.after_state is not None
    # Verify
    verifier = VerificationAgent()
    before = {"error_rate_pct": 34, "latency_p95_ms": 220}
    after = {"error_rate_pct": 0.5, "latency_p95_ms": 180}
    verification = verifier.verify(ev.incident_id, result, before, after)
    assert verification.verification_status.value == "RESOLVED"
    assert verification.resolved is True

def test_traffic_overload_scaling():
    path = "data/incidents/incident_005_traffic_overload.json"
    with open(path) as f:
        ev = IncidentEvidence(**json.load(f))
    wf = InvestigationWorkflow()
    state = wf.run(ev)
    rem = RemediationAgent()
    # Force traffic category
    plan = rem.plan(ev, state.final_report, validated_category="traffic_overload")
    assert plan.recommended_action == "cloud_run_scale_within_limits"
    mgr = ApprovalManager()
    appr = mgr.create_request(incident_id=ev.incident_id, action=plan.recommended_action, target_resource=plan.target_resource,
                              rationale=plan.expected_effect, root_cause=plan.root_cause, confidence=plan.confidence, risk=plan.estimated_risk.value,
                              expected_impact=plan.expected_effect, rollback_plan=plan.rollback_plan)
    mgr.approve(appr.approval_id)
    executor = ExecutorAgent()
    result = executor.execute(mgr.get(appr.approval_id), {"max_instances": 10})
    assert result.status.value == "SUCCESS"
    verifier = VerificationAgent()
    verification = verifier.verify(ev.incident_id, result, {"error_rate_pct":30,"latency_p95_ms":4000}, {"error_rate_pct":1.5,"latency_p95_ms":200})
    assert verification.verification_status.value in ("RESOLVED","PARTIALLY_RESOLVED")

def test_dependency_outage_no_unsafe_restart():
    path = "data/incidents/incident_004_dependency_outage.json"
    with open(path) as f:
        ev = IncidentEvidence(**json.load(f))
    wf = InvestigationWorkflow()
    state = wf.run(ev)
    rem = RemediationAgent()
    plan = rem.plan(ev, state.final_report, validated_category="dependency_failure")
    # Should NOT propose rollback of healthy upstream
    assert plan.recommended_action != "cloud_run_rollback" or "downstream" in plan.expected_effect.lower() or "upstream" in plan.preconditions[0].lower()
    assert "do not restart healthy upstream" in " ".join(plan.preconditions).lower() or plan.mitigation_type.value in ("WORKAROUND",)

def test_state_machine_valid_transitions():
    sm = IncidentStateMachine(IncidentState.DETECTED)
    sm.transition(IncidentState.INVESTIGATING)
    sm.transition(IncidentState.RCA_GENERATED)
    sm.transition(IncidentState.RCA_VALIDATED)
    sm.transition(IncidentState.REMEDIATION_PLANNED)
    sm.transition(IncidentState.APPROVAL_PENDING)
    sm.transition(IncidentState.APPROVED)
    sm.transition(IncidentState.REMEDIATING)
    sm.transition(IncidentState.VERIFYING)
    sm.transition(IncidentState.RESOLVED)
    assert sm.state == IncidentState.RESOLVED
    # Invalid should raise
    sm2 = IncidentStateMachine(IncidentState.DETECTED)
    try:
        sm2.transition(IncidentState.RESOLVED)
        assert False, "Should have raised"
    except ValueError:
        pass

def test_memory_store_and_retrieval(tmp_path=None):
    # Use file fallback
    store = MemoryStore(use_bigquery=False)
    from memory.schemas import IncidentMemoryRecord
    # Clear previous
    if store.load_all():
        # keep but test retrieval
        pass
    rec = IncidentMemoryRecord(incident_id="INC-TEST-MEM-001", service="checkout-service", symptoms=["pool exhausted"], timeline=[], root_cause="pool", root_cause_category="connection_pool_exhaustion", supporting_evidence=[], blast_radius={}, final_status="RESOLVED", timestamps={}, confidence=0.92)
    store.save(rec)
    results = find_similar_incidents(service="checkout-service", symptoms=["pool exhausted"], root_cause_category="connection_pool_exhaustion", limit=2, store=store)
    assert any(r["incident_id"]=="INC-TEST-MEM-001" for r in results)

def test_verification_regression_detected():
    verifier = VerificationAgent()
    from agents.executor_agent.schemas import ExecutionResult, ExecutionStatus
    exec_res = ExecutionResult(execution_id="EXEC-TEST", approval_id="APPROVAL-TEST", incident_id="INC-TEST", action="cloud_run_rollback", target_resource="projects/p/locations/us-central1/services/svc", start_time="2026-09-05T00:00:00Z", end_time="2026-09-05T00:01:00Z", status=ExecutionStatus.SUCCESS)
    verification = verifier.verify("INC-TEST", exec_res, {"error_rate_pct":5,"latency_p95_ms":200}, {"error_rate_pct":15,"latency_p95_ms":300})
    assert verification.verification_status.value == "REGRESSED"
