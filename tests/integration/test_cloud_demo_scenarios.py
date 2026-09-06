"""
Tests for the 4 Google Cloud Demo Scenarios:
  - Scenario 1: Database timeout
  - Scenario 2: High latency / Pool exhaustion
  - Scenario 3: Faulty revision / bad deployment
  - Scenario 4: Downstream orders-service failure
"""
import os
import json
from agents.rca_agent.agent import CloudRCAAgent
from schemas.evidence import IncidentEvidence
from schemas.rca import RCAResult

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


def test_scenario_1_db_timeout():
    inc_file = os.path.join(DATA_DIR, "incidents", "incident_001_db_timeout.json")
    rca_file = os.path.join(DATA_DIR, "expected_rcas", "rca_001_db_timeout.json")

    agent = CloudRCAAgent()
    pred = agent.analyze(inc_file)

    with open(rca_file, "r", encoding="utf-8") as f:
        expected = json.load(f)

    assert pred.root_cause_category == expected["root_cause_category"]
    assert pred.confidence_score >= 0.90
    assert any("DATABASE_CONNECTION_TIMEOUT" in e for e in pred.evidence)
    assert any("CPU" in ce for ce in pred.contradictory_evidence)


def test_scenario_2_high_latency_pool_exhaustion():
    inc_file = os.path.join(DATA_DIR, "incidents", "incident_002_pool_exhaustion.json")
    rca_file = os.path.join(DATA_DIR, "expected_rcas", "rca_002_pool_exhaustion.json")

    agent = CloudRCAAgent()
    pred = agent.analyze(inc_file)

    with open(rca_file, "r", encoding="utf-8") as f:
        expected = json.load(f)

    assert pred.root_cause_category == expected["root_cause_category"]
    assert pred.confidence_score >= 0.90
    assert any("pool" in e.lower() for e in pred.evidence)


def test_scenario_3_bad_deployment():
    inc_file = os.path.join(DATA_DIR, "incidents", "incident_003_bad_deployment.json")
    rca_file = os.path.join(DATA_DIR, "expected_rcas", "rca_003_bad_deployment.json")

    agent = CloudRCAAgent()
    pred = agent.analyze(inc_file)

    with open(rca_file, "r", encoding="utf-8") as f:
        expected = json.load(f)

    assert pred.root_cause_category == expected["root_cause_category"]
    assert pred.confidence_score >= 0.90
    assert "roll back" in pred.recommended_action.lower() or "rollback" in pred.recommended_action.lower()


def test_scenario_4_downstream_orders_service_failure():
    inc_file = os.path.join(DATA_DIR, "incidents", "incident_004_dependency_outage.json")
    rca_file = os.path.join(DATA_DIR, "expected_rcas", "rca_004_dependency_outage.json")

    agent = CloudRCAAgent()
    pred = agent.analyze(inc_file)

    with open(rca_file, "r", encoding="utf-8") as f:
        expected = json.load(f)

    assert pred.root_cause_category == expected["root_cause_category"]
    assert "orders-service" in pred.affected_services
    assert pred.confidence_score >= 0.90
