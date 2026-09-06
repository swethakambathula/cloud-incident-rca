"""
Unit tests for tools/normalizer.py.
"""
from tools.normalizer import normalize_evidence
from schemas.evidence import IncidentEvidence


def test_normalize_evidence_basic():
    raw_logs = [
        {
            "timestamp": "2026-09-05T14:10:00Z",
            "severity": "ERROR",
            "payload": {
                "error_code": "DATABASE_CONNECTION_TIMEOUT",
                "endpoint": "/simulate/error",
                "message": "Connection timed out"
            },
            "http_request": {
                "status": 500,
                "request_url": "https://demo.run.app/simulate/error"
            }
        },
        {
            "timestamp": "2026-09-05T14:10:05Z",
            "severity": "ERROR",
            "payload": {
                "error_code": "DATABASE_CONNECTION_TIMEOUT",
                "endpoint": "/simulate/error"
            },
            "http_request": {
                "status": 500,
                "request_url": "https://demo.run.app/simulate/error"
            }
        }
    ]

    raw_metrics = {
        "baseline": {
            "error_rate_pct": 0.1,
            "latency_p95_ms": 150.0,
            "request_count": 500.0,
            "cpu_utilization_pct": 20.0,
            "memory_utilization_pct": 35.0
        },
        "incident": {
            "error_rate_pct": 18.0,
            "latency_p95_ms": 4200.0,
            "request_count": 520.0,
            "cpu_utilization_pct": 22.0,
            "memory_utilization_pct": 36.0
        }
    }

    evidence = normalize_evidence(
        incident_id="INC-NORM-01",
        project_id="test-project",
        service_name="demo-service",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        raw_logs=raw_logs,
        raw_metrics=raw_metrics,
        revision_name="demo-service-00001",
        region="us-central1"
    )

    assert isinstance(evidence, IncidentEvidence)
    assert evidence.incident_id == "INC-NORM-01"
    assert evidence.severity == "P1"
    assert len(evidence.application_errors) == 1
    assert evidence.application_errors[0]["error_code"] == "DATABASE_CONNECTION_TIMEOUT"
    assert evidence.application_errors[0]["count"] == 2
    assert evidence.latency["severity"] == "CRITICAL"
    assert evidence.cpu_utilization["severity"] == "NORMAL"
    assert "/simulate/error" in evidence.blast_radius["affected_endpoints"]
