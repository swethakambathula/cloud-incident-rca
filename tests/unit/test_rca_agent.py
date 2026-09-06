"""
Unit tests for agents/rca_agent/agent.py.
"""
import os
from agents.rca_agent.agent import CloudRCAAgent
from schemas.evidence import IncidentEvidence
from schemas.rca import RCAResult

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


def test_rca_agent_scenarios():
    agent = CloudRCAAgent()

    test_cases = [
        ("incident_001_db_timeout.json", "database_connectivity"),
        ("incident_002_pool_exhaustion.json", "connection_pool_exhaustion"),
        ("incident_003_bad_deployment.json", "faulty_revision"),
        ("incident_004_dependency_outage.json", "dependency_failure"),
        ("incident_005_traffic_overload.json", "traffic_overload"),
        ("incident_006_config_regression.json", "configuration_regression"),
    ]

    for inc_file, expected_cat in test_cases:
        inc_path = os.path.join(DATA_DIR, "incidents", inc_file)
        result = agent.analyze(inc_path)

        assert isinstance(result, RCAResult)
        assert result.root_cause_category == expected_cat, f"Mismatch for {inc_file}: got {result.root_cause_category}"
        assert 0.85 <= result.confidence_score <= 1.0, f"Confidence not calibrated for {inc_file}"
        assert len(result.evidence) > 0, "Agent must cite evidence"
        assert len(result.contradictory_evidence) > 0, "Agent must identify contradictory evidence"
        assert len(result.affected_services) > 0
        assert result.remediation_risk in ["LOW", "MEDIUM", "HIGH"]


def test_rca_agent_unknown_fallback():
    agent = CloudRCAAgent()
    empty_evidence = IncidentEvidence(
        incident_id="INC-EMPTY",
        start_time="2026-09-05T12:00:00Z",
        end_time="2026-09-05T12:15:00Z",
        project_id="test",
        service_name="test-svc",
        severity="P3",
        symptoms=[]
    )
    result = agent.analyze(empty_evidence)
    assert result.root_cause_category == "unknown"
    assert result.confidence_score <= 0.40
    assert "unknown" in result.root_cause.lower()
