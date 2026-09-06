"""
Knowledge grounding tests
"""
from schemas.evidence import IncidentEvidence
from agents.knowledge_agent.agent import KnowledgeAgent
from tools.knowledge_tools import search_knowledge

def test_retrieved_historical_incidents_exist():
    evidence = IncidentEvidence(
        incident_id="INC-KB-01",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="p",
        service_name="checkout-service",
        severity="P1",
        symptoms=["DATABASE_CONNECTION_TIMEOUT"],
        application_errors=[{"error_code":"DATABASE_CONNECTION_TIMEOUT","count":10}],
    )
    agent = KnowledgeAgent()
    findings = agent.investigate(evidence)
    assert len(findings) > 0
    for f in findings:
        assert f.source_id
        assert f.source_type in ("runbook","architecture","historical_incident")
        # Verify file exists
        from pathlib import Path
        kb_root = Path(__file__).parent.parent.parent / "knowledge"
        assert (kb_root / f.source_id).exists(), f"source_id {f.source_id} does not exist on disk"
        assert f.similarity_score > 0

def test_irrelevant_incidents_rejected():
    # Query for a nonsense pattern not in KB should yield few or low similarity
    res = search_knowledge("completely irrelevant unicorn quantum entanglement", top_k=5)
    # Either empty or low similarity
    if res:
        assert all(r["similarity_score"] < 0.5 for r in res)

def test_historical_similarity_not_override():
    # Even with historical similarity, current evidence should drive RCA
    # If DB timeout historical matches but current evidence is deployment fault, RCA should prioritize deployment metrics
    from orchestration.workflow import InvestigationWorkflow
    import json, os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data","incidents","incident_003_bad_deployment.json")
    with open(path) as f:
        data = json.load(f)
    evidence = IncidentEvidence(**data)
    wf = InvestigationWorkflow()
    state = wf.run(evidence)
    # Top hypothesis should be faulty_revision, not database_connectivity even though DB timeout runbook exists
    top = max(state.hypotheses, key=lambda h: h.confidence_score)
    assert top.root_cause_category == "faulty_revision"
