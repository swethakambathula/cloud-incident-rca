"""
Unit tests for schemas: IncidentEvidence and RCAResult.
"""
import pytest
from pydantic import ValidationError
from schemas.evidence import IncidentEvidence
from schemas.rca import RCAResult


def test_incident_evidence_valid():
    evidence = IncidentEvidence(
        incident_id="inc-101",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="my-gcp-project",
        service_name="demo-service",
        revision_name="demo-service-00002-v1",
        region="us-central1",
        severity="P1",
        symptoms=["Elevated HTTP 500 error rate", "Database connection timeout logs"],
        application_errors=[
            {"error_code": "DATABASE_CONNECTION_TIMEOUT", "count": 42}
        ],
        request_errors=[
            {"status_code": 500, "endpoint": "/simulate/error", "count": 42}
        ],
        latency={"p50_ms": 120, "p95_ms": 3200},
        request_count={"total": 1200, "error_rate_pct": 3.5},
        cpu_utilization={"baseline_pct": 20.0, "incident_pct": 22.0, "delta_pct": 10.0, "severity": "NORMAL"},
        memory_utilization={"baseline_pct": 40.0, "incident_pct": 42.0, "delta_pct": 5.0, "severity": "NORMAL"},
        recent_deployments=[],
        dependencies=[{"service": "orders-db", "status": "UNREACHABLE"}],
        traces=[{"trace_id": "abc123xyz", "duration_ms": 3500}],
        blast_radius={"affected_endpoints": ["/simulate/error"], "scope": "service-wide"},
        raw_evidence=[{"type": "LOG", "message": "DATABASE_CONNECTION_TIMEOUT"}]
    )
    assert evidence.incident_id == "inc-101"
    assert evidence.severity == "P1"
    assert len(evidence.symptoms) == 2
    assert evidence.cpu_utilization["severity"] == "NORMAL"


def test_incident_evidence_missing_required_field():
    with pytest.raises(ValidationError):
        IncidentEvidence(
            # missing incident_id, start_time, end_time, project_id, service_name, severity
            symptoms=["Some symptom"]
        )


def test_rca_result_valid():
    rca = RCAResult(
        incident_id="inc-101",
        root_cause="Database network connectivity timed out after firewall rule change",
        root_cause_category="database_connectivity",
        confidence_score=0.94,
        evidence=[
            "42 DATABASE_CONNECTION_TIMEOUT application logs observed",
            "HTTP 500 rate elevated to 3.5% specifically on database-backed endpoints"
        ],
        contradictory_evidence=[
            "CPU utilization remained normal at 22% (eliminating CPU exhaustion)",
            "Memory utilization remained stable at 42% (eliminating OOM)"
        ],
        affected_services=["demo-service"],
        blast_radius="Localized to /simulate/error endpoint and database transactions",
        recommended_action="Verify database VPC connector and database host availability",
        remediation_risk="LOW",
        additional_checks_required=["Check Cloud SQL metrics", "Verify VPC firewall egress rules"]
    )
    assert rca.incident_id == "inc-101"
    assert rca.confidence_score == 0.94
    assert rca.remediation_risk == "LOW"


def test_rca_result_invalid_confidence():
    with pytest.raises(ValidationError):
        RCAResult(
            incident_id="inc-101",
            root_cause="Test",
            root_cause_category="test",
            confidence_score=1.5,  # Invalid: must be <= 1.0
            evidence=[],
            contradictory_evidence=[],
            affected_services=["svc"],
            blast_radius="local",
            recommended_action="restart",
            remediation_risk="LOW",
            additional_checks_required=[]
        )
