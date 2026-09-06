"""
Integration test for end-to-end incident collection and RCA diagnosis.
Verifies:
  - collect_incident_evidence produces a valid IncidentEvidence object
  - CloudRCAAgent analyzes the collected evidence and returns an RCAResult
"""
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
from tools.correlation import collect_incident_evidence
from agents.rca_agent.agent import CloudRCAAgent
from schemas.evidence import IncidentEvidence
from schemas.rca import RCAResult


def test_collect_incident_evidence_end_to_end():
    mock_entry = MagicMock()
    mock_entry.timestamp = datetime.now(timezone.utc)
    mock_entry.severity = "ERROR"
    mock_entry.payload = {
        "error_code": "DATABASE_CONNECTION_TIMEOUT",
        "dependency": "orders-db",
        "message": "Connection timed out"
    }
    mock_entry.text_payload = None
    mock_entry.http_request = {"status": 500, "request_url": "https://service/simulate/error"}
    mock_entry.trace = "projects/test/traces/test-trace-e2e-001"
    mock_entry.resource.labels = {"service_name": "checkout-service"}

    mock_log_client = MagicMock()
    mock_log_client.list_entries.return_value = [mock_entry]

    with patch("tools.logging_tools._get_client", return_value=mock_log_client), \
         patch("tools.monitoring_tools._get_metric_client", return_value=None), \
         patch("tools.deployment_tools._get_services_client", return_value=None), \
         patch("tools.deployment_tools._get_revisions_client", return_value=None):
        evidence = collect_incident_evidence(
            project_id="cloud-incident-prod",
            service_name="checkout-service",
            incident_start="2026-09-05T14:00:00Z",
            incident_end="2026-09-05T14:15:00Z",
            minutes_window=15
        )

        assert isinstance(evidence, IncidentEvidence)
        assert evidence.service_name == "checkout-service"
        assert evidence.severity in ["P1", "P2", "P3"]
        assert len(evidence.application_errors) > 0
        assert evidence.application_errors[0]["error_code"] == "DATABASE_CONNECTION_TIMEOUT"


def test_end_to_end_rca_pipeline():
    mock_entry = MagicMock()
    mock_entry.timestamp = datetime.now(timezone.utc)
    mock_entry.severity = "ERROR"
    mock_entry.payload = {
        "error_code": "DATABASE_CONNECTION_TIMEOUT",
        "dependency": "orders-db",
        "message": "Connection timed out"
    }
    mock_entry.text_payload = None
    mock_entry.http_request = {"status": 500, "request_url": "https://service/simulate/error"}
    mock_entry.trace = "projects/test/traces/test-trace-e2e-002"
    mock_entry.resource.labels = {"service_name": "checkout-service"}

    mock_log_client = MagicMock()
    mock_log_client.list_entries.return_value = [mock_entry]

    with patch("tools.logging_tools._get_client", return_value=mock_log_client), \
         patch("tools.monitoring_tools._get_metric_client", return_value=None), \
         patch("tools.deployment_tools._get_services_client", return_value=None), \
         patch("tools.deployment_tools._get_revisions_client", return_value=None):
        evidence = collect_incident_evidence(
            project_id="cloud-incident-prod",
            service_name="checkout-service",
            incident_start="2026-09-05T14:00:00Z",
            incident_end="2026-09-05T14:15:00Z",
            minutes_window=15
        )

        agent = CloudRCAAgent()
        rca = agent.analyze(evidence)

        assert isinstance(rca, RCAResult)
        assert rca.root_cause_category == "database_connectivity"
        assert 0.0 <= rca.confidence_score <= 1.0
        assert rca.remediation_risk in ["LOW", "MEDIUM", "HIGH"]
        assert len(rca.affected_services) > 0
        assert len(rca.evidence) > 0
