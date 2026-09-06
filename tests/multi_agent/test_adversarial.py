"""
Adversarial RCA tests: correlation should not produce wrong RCA.
"""
import json, os
from schemas.evidence import IncidentEvidence
from orchestration.workflow import InvestigationWorkflow

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "incidents")

def test_deployment_proximity_but_dependency_cause():
    """
    Deployment occurs 5 min before incident but actual cause is orders-service outage.
    Deployment hypothesis should be considered but rejected after trace evidence.
    """
    # Use incident_004 which has deployment 4 hours earlier but simulate near-deployment adversarial
    path = os.path.join(DATA_DIR, "incident_004_dependency_outage.json")
    with open(path) as f:
        data = json.load(f)
    # Inject adversarial near deployment 5 min before (start is 15:30)
    data["recent_deployments"] = [{
        "revision_name": "checkout-service-00004-v1-adversarial",
        "deployed_at": "2026-09-05T15:28:00Z",  # 2 min before start 15:30
        "traffic_percent": 100
    }] + data.get("recent_deployments", [])
    evidence = IncidentEvidence(**data)
    wf = InvestigationWorkflow()
    state = wf.run(evidence)
    # Ensure deployment hypothesis exists but is not top accepted (dependency should win)
    categories = [h.root_cause_category for h in state.hypotheses]
    assert "faulty_revision" in categories, "Deployment hypothesis should be considered"
    assert "dependency_failure" in categories
    # Critic should reject or weakly support deployment when dependency clearly failing
    dep_hyp = next((h for h in state.hypotheses if h.root_cause_category=="dependency_failure"), None)
    dep_val = next((v for v in state.validated_hypotheses+state.rejected_hypotheses if v.hypothesis_id==dep_hyp.hypothesis_id), None) if dep_hyp else None
    assert dep_val and dep_val.accepted, "Dependency hypothesis should be accepted"
    # Deployment should be rejected or lower confidence when dependency evidence strong
    deploy_hyp = next((h for h in state.hypotheses if h.root_cause_category=="faulty_revision"), None)
    deploy_val = next((v for v in state.validated_hypotheses+state.rejected_hypotheses if v.hypothesis_id==deploy_hyp.hypothesis_id), None) if deploy_hyp else None
    # Not strictly rejected but confidence should be lower than dependency
    if deploy_val and dep_val:
        assert deploy_val.adjusted_confidence < dep_val.adjusted_confidence, "Deployment should be lower confidence than true dependency cause"

def test_cpu_normal_rejects_overload():
    path = os.path.join(DATA_DIR, "incident_001_db_timeout.json")
    with open(path) as f:
        data = json.load(f)
    evidence = IncidentEvidence(**data)
    # incident_001 has CPU normal 24%, but high latency and 500s. Overload should be rejected.
    wf = InvestigationWorkflow()
    state = wf.run(evidence)
    overload_hyp = next((h for h in state.hypotheses if h.root_cause_category=="traffic_overload"), None)
    if overload_hyp:
        val = next((v for v in state.validated_hypotheses+state.rejected_hypotheses if v.hypothesis_id==overload_hyp.hypothesis_id), None)
        assert val is not None
        # Should be REJECTED or WEAK because CPU normal
        assert val.validation_status.value in ("REJECTED","WEAK","INSUFFICIENT_EVIDENCE") or val.adjusted_confidence < 0.4
