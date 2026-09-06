"""
Integration test for full workflow across 6 ground truth scenarios.
"""
import os, json
from schemas.evidence import IncidentEvidence
from orchestration.workflow import InvestigationWorkflow

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")

SCENARIOS = [
    ("incident_001_db_timeout.json", "database_connectivity"),
    ("incident_002_pool_exhaustion.json", "connection_pool_exhaustion"),
    ("incident_003_bad_deployment.json", "faulty_revision"),
    ("incident_004_dependency_outage.json", "dependency_failure"),
    ("incident_005_traffic_overload.json", "traffic_overload"),
    ("incident_006_config_regression.json", "configuration_regression"),
]

def test_workflow_covers_all_six_scenarios():
    wf = InvestigationWorkflow()
    for inc_file, expected_cat in SCENARIOS:
        path = os.path.join(DATA_DIR, "incidents", inc_file)
        with open(path) as f:
            data=json.load(f)
        evidence=IncidentEvidence(**data)
        state=wf.run(evidence)
        # Exit criteria: hypotheses generated
        assert len(state.hypotheses) >= 2 or expected_cat == "unknown"
        # Determine best predicted via validated accepted highest conf
        accepted = [v for v in state.validated_hypotheses if v.accepted]
        if accepted:
            best_val = max(accepted, key=lambda v: v.adjusted_confidence)
            hyp = next((h for h in state.hypotheses if h.hypothesis_id==best_val.hypothesis_id), None)
            predicted = hyp.root_cause_category if hyp else state.hypotheses[0].root_cause_category
        else:
            predicted = state.hypotheses[0].root_cause_category if state.hypotheses else "unknown"
        assert predicted == expected_cat, f"{inc_file} predicted {predicted} vs expected {expected_cat}"
        # Exit criteria: confidence recalibrated not 1.0
        assert all(h.confidence_score <= 0.99 for h in state.hypotheses)
        # Blast radius
        assert state.blast_radius is not None
        assert state.blast_radius.classification in ("LOCALIZED","SERVICE_LEVEL","MULTI_SERVICE","REGIONAL","SYSTEM_WIDE")
        # Timeline deterministically generated from evidence
        assert len(state.final_report.timeline) >= 1
        # Trace observability
        assert len(state.trace.agent_traces) >= 5
        # Final report exists
        assert state.final_report is not None

def test_verbose_mode_does_not_crash():
    import json, os
    path = os.path.join(DATA_DIR,"incidents","incident_001_db_timeout.json")
    with open(path) as f:
        data=json.load(f)
    evidence=IncidentEvidence(**data)
    wf=InvestigationWorkflow()
    state=wf.run(evidence, verbose=True)
    assert state.final_report.confidence > 0
