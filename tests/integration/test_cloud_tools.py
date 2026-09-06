"""
Integration tests for Google Cloud Telemetry tools:
  - Logging retrieval
  - Monitoring retrieval
  - Deployment revision retrieval
  - Trace extraction
Tests verify both mocked GCP API responses and graceful offline degradation.
"""
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from tools.logging_tools import (
    get_service_logs,
    get_error_logs,
    get_logs_for_time_window,
    get_request_logs,
    get_application_logs,
    get_error_frequency,
)
from tools.monitoring_tools import (
    get_request_count,
    get_error_rate,
    get_request_latency,
    get_cpu_utilization,
    get_memory_utilization,
    compare_baseline_to_incident,
)
from tools.deployment_tools import (
    get_current_revision,
    get_recent_revisions,
    compare_revisions,
)
from tools.trace_tools import (
    get_trace_id_from_log,
    get_trace_details,
    get_related_trace_events,
)

PROJECT_ID = "mock-gcp-project"
SERVICE_NAME = "checkout-service"


def test_logging_tools_with_mocked_client():
    mock_entry = MagicMock()
    mock_entry.timestamp = datetime.now(timezone.utc)
    mock_entry.severity = "ERROR"
    mock_entry.payload = {"error_code": "DATABASE_CONNECTION_TIMEOUT", "message": "Connection timed out"}
    mock_entry.text_payload = None
    mock_entry.http_request = {"status": 500, "request_url": "https://service/simulate/error"}
    mock_entry.trace = f"projects/{PROJECT_ID}/traces/test-trace-123456"
    mock_entry.resource.labels = {"service_name": SERVICE_NAME}

    mock_client = MagicMock()
    mock_client.list_entries.return_value = [mock_entry]

    with patch("tools.logging_tools._get_client", return_value=mock_client):
        logs = get_service_logs(PROJECT_ID, SERVICE_NAME, limit=5)
        assert len(logs) == 1
        assert logs[0]["severity"] == "ERROR"
        assert logs[0]["trace_id"] == "test-trace-123456"

        err_logs = get_error_logs(PROJECT_ID, SERVICE_NAME, limit=5)
        assert len(err_logs) == 1

        window_logs = get_logs_for_time_window(PROJECT_ID, SERVICE_NAME, "2026-09-05T14:00:00Z", "2026-09-05T14:15:00Z")
        assert len(window_logs) == 1

        freq = get_error_frequency(PROJECT_ID, SERVICE_NAME, "2026-09-05T14:00:00Z", "2026-09-05T14:15:00Z")
        assert freq.get("DATABASE_CONNECTION_TIMEOUT") == 1


def test_logging_tools_offline_fallback():
    with patch("tools.logging_tools._get_client", return_value=None):
        logs = get_service_logs(PROJECT_ID, SERVICE_NAME)
        assert logs == []
        freq = get_error_frequency(PROJECT_ID, SERVICE_NAME, "2026-09-05T14:00:00Z", "2026-09-05T14:15:00Z")
        assert freq == {}


def test_monitoring_tools_with_mocked_client():
    mock_point = MagicMock()
    mock_point.value.int64_value = 450
    mock_point.value.double_value = 0.25

    mock_series = MagicMock()
    mock_series.points = [mock_point]
    mock_series.metric.labels = {"response_code_class": "2xx"}

    mock_client = MagicMock()
    mock_client.list_time_series.return_value = [mock_series]

    with patch("tools.monitoring_tools._get_metric_client", return_value=mock_client):
        reqs = get_request_count(PROJECT_ID, SERVICE_NAME, minutes=15)
        assert reqs["total_requests"] == 450

        latency = get_request_latency(PROJECT_ID, SERVICE_NAME, minutes=15)
        assert latency["p95_latency_ms"] == 0.25

        comparison = compare_baseline_to_incident(PROJECT_ID, SERVICE_NAME, baseline_minutes=15, incident_minutes=15)
        assert "error_rate" in comparison
        assert "latency_p95" in comparison
        assert "cpu" in comparison


def test_monitoring_tools_offline_fallback():
    with patch("tools.monitoring_tools._get_metric_client", return_value=None):
        reqs = get_request_count(PROJECT_ID, SERVICE_NAME)
        assert reqs["status"] == "CLIENT_UNAVAILABLE"

        err = get_error_rate(PROJECT_ID, SERVICE_NAME)
        assert err["status"] == "CLIENT_UNAVAILABLE"


def test_deployment_tools_execution():
    mock_rev = MagicMock()
    mock_rev.name = f"projects/{PROJECT_ID}/locations/us-central1/services/{SERVICE_NAME}/revisions/{SERVICE_NAME}-00004-v1"
    mock_rev.create_time = datetime.now(timezone.utc)
    mock_rev.containers = []

    mock_client = MagicMock()
    mock_client.list_revisions.return_value = [mock_rev]

    with patch("tools.deployment_tools._get_revisions_client", return_value=mock_client), \
         patch("tools.deployment_tools._get_services_client", return_value=None):
        cur_rev = get_current_revision(PROJECT_ID, "us-central1", SERVICE_NAME)
        assert cur_rev is not None

        recent = get_recent_revisions(PROJECT_ID, "us-central1", SERVICE_NAME, limit=3)
        assert isinstance(recent, list)
        assert len(recent) > 0

    rev_a = {"containers": [{"image": "gcr.io/app:v1", "env": {"ENV": "prod"}}]}
    rev_b = {"containers": [{"image": "gcr.io/app:v2", "env": {"ENV": "prod", "KEY": "val"}}]}
    diff = compare_revisions(rev_a, rev_b)
    assert diff["image_changed"] is True
    assert "KEY" in diff["added_env_vars"]


def test_trace_tools_extraction():
    log_sample = {
        "trace": f"projects/{PROJECT_ID}/traces/4bf92f3577b34da6a3ce929d0e0e4736",
        "message": "Sample request"
    }
    tid = get_trace_id_from_log(log_sample)
    assert tid == "4bf92f3577b34da6a3ce929d0e0e4736"

    details = get_trace_details(PROJECT_ID, tid)
    assert details["trace_id"] == tid
