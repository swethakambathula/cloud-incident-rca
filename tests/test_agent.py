"""
Unit tests for CloudRCAAgent.
"""
import os
import pytest
from agents.rca_agent.agent import CloudRCAAgent


def test_agent_analyze_db_pool():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    incident_file = os.path.join(base_dir, "data", "incidents", "incident_001_db_pool.json")

    agent = CloudRCAAgent()
    result = agent.analyze_incident(incident_file)

    assert result.incident_id == "INC-001"
    assert "postgresql-cluster" in result.root_cause_component or "payment-api" in result.root_cause_component
    assert result.confidence_score >= 0.85
    assert len(result.remediation_steps) >= 1
    assert len(result.causal_chain) >= 1
