"""
Supervisor routing tests.
"""
from schemas.evidence import IncidentEvidence
from orchestration.routing import select_agents
from agents.supervisor.agent import SupervisorAgent

def test_not_every_agent_always_invoked():
    # Minimal evidence with no deployment should not invoke deployment_agent
    evidence = IncidentEvidence(
        incident_id="INC-ROUTING-01",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="test-proj",
        service_name="checkout-service",
        severity="P1",
        symptoms=["pool exhausted"],
        application_errors=[{"error_code": "DATABASE_CONNECTION_POOL_EXHAUSTED", "count": 10}],
        recent_deployments=[],
        dependencies=[{"name": "orders-db", "status": "HEALTHY"}],
        traces=[],
    )
    agents = select_agents(evidence)
    assert "deployment_agent" not in agents, "Should not invoke deployment agent when no deployments"
    assert "log_agent" in agents
    assert "metrics_agent" in agents

def test_agents_selected_based_on_symptoms():
    evidence_with_deploy = IncidentEvidence(
        incident_id="INC-ROUTING-02",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="test-proj",
        service_name="checkout-service",
        severity="P1",
        symptoms=["new revision deployed"],
        application_errors=[{"error_code": "NULL_POINTER_EXCEPTION", "count": 5}],
        recent_deployments=[{"revision_name": "rev-5", "deployed_at":"2026-09-05T13:58:00Z","traffic_percent":100}],
        dependencies=[],
        traces=[{"trace_id":"t1","duration_ms":200}],
    )
    agents = select_agents(evidence_with_deploy)
    assert "deployment_agent" in agents
    assert "trace_agent" in agents

def test_max_rounds_respected():
    from schemas.evidence import IncidentEvidence
    from orchestration.state import InvestigationState
    evidence = IncidentEvidence(
        incident_id="INC-ROUTING-03",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="test-proj",
        service_name="svc",
        severity="P1",
        symptoms=["test"],
    )
    state = InvestigationState(incident_id=evidence.incident_id, incident_evidence=evidence)
    # Try to exceed max
    for i in range(5):
        state.increment_round_with_tasks([f"task-{i}"])
    assert state.investigation_round == 3
    assert state.investigation_status == "MAX_ROUNDS_REACHED"
