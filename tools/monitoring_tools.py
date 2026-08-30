"""
Google Cloud Monitoring Tools for Cloud Incident RCA Agent.
Fetches metrics (Request Count, Error Rates, Request Latencies) from Cloud Monitoring API.
"""
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

try:
    from google.cloud import monitoring_v3
    HAS_GCP_MONITORING = True
except ImportError:
    HAS_GCP_MONITORING = False


def get_request_count(
    project_id: str,
    service_name: str,
    minutes: int = 30,
) -> Dict[str, Any]:
    """Queries total request count for a Cloud Run service over the last N minutes."""
    if not HAS_GCP_MONITORING:
        return {"total_requests": 0, "status": "google-cloud-monitoring not installed"}

    try:
        client = monitoring_v3.MetricServiceClient()
        project_name = f"projects/{project_id}"

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)

        interval = monitoring_v3.TimeInterval(
            {
                "end_time": {"seconds": int(now.timestamp())},
                "start_time": {"seconds": int(start_time.timestamp())},
            }
        )

        filter_str = (
            f'metric.type = "run.googleapis.com/request_count" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        aggregation = monitoring_v3.Aggregation(
            {
                "alignment_period": {"seconds": minutes * 60},
                "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
            }
        )

        results = client.list_time_series(
            request={
                "name": project_name,
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": aggregation,
            }
        )

        total_count = 0
        time_series_data = []

        for series in results:
            for point in series.points:
                val = point.value.int64_value
                total_count += val
                time_series_data.append({
                    "response_code": series.metric.labels.get("response_code_class", "2xx"),
                    "count": val
                })

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": total_count,
            "breakdown": time_series_data
        }

    except Exception as e:
        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": 0,
            "error": str(e)
        }


def get_error_rate(
    project_id: str,
    service_name: str,
    minutes: int = 30,
) -> Dict[str, Any]:
    """Calculates HTTP 5xx error percentage over the last N minutes."""
    req_data = get_request_count(project_id, service_name, minutes=minutes)
    total_requests = req_data.get("total_requests", 0)

    if total_requests == 0:
        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": 0,
            "error_requests": 0,
            "error_rate_percent": 0.0,
            "status": "NO_TRAFFIC"
        }

    try:
        client = monitoring_v3.MetricServiceClient()
        project_name = f"projects/{project_id}"

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)

        interval = monitoring_v3.TimeInterval(
            {
                "end_time": {"seconds": int(now.timestamp())},
                "start_time": {"seconds": int(start_time.timestamp())},
            }
        )

        filter_str = (
            f'metric.type = "run.googleapis.com/request_count" AND '
            f'resource.labels.service_name = "{service_name}" AND '
            f'metric.labels.response_code_class = "5xx"'
        )

        aggregation = monitoring_v3.Aggregation(
            {
                "alignment_period": {"seconds": minutes * 60},
                "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
            }
        )

        results = client.list_time_series(
            request={
                "name": project_name,
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": aggregation,
            }
        )

        error_count = 0
        for series in results:
            for point in series.points:
                error_count += point.value.int64_value

        error_rate_pct = (error_count / total_requests) * 100.0 if total_requests > 0 else 0.0

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": total_requests,
            "error_requests": error_count,
            "error_rate_percent": round(error_rate_pct, 2)
        }

    except Exception as e:
        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": total_requests,
            "error_requests": 0,
            "error_rate_percent": 0.0,
            "error": str(e)
        }


def get_request_latency(
    project_id: str,
    service_name: str,
    minutes: int = 30,
) -> Dict[str, Any]:
    """Queries latency distribution (p50, p95, p99) for a service."""
    if not HAS_GCP_MONITORING:
        return {"status": "google-cloud-monitoring not installed"}

    try:
        client = monitoring_v3.MetricServiceClient()
        project_name = f"projects/{project_id}"

        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)

        interval = monitoring_v3.TimeInterval(
            {
                "end_time": {"seconds": int(now.timestamp())},
                "start_time": {"seconds": int(start_time.timestamp())},
            }
        )

        filter_str = (
            f'metric.type = "run.googleapis.com/request_latencies" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        aggregation = monitoring_v3.Aggregation(
            {
                "alignment_period": {"seconds": minutes * 60},
                "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_PERCENTILE_95,
            }
        )

        results = client.list_time_series(
            request={
                "name": project_name,
                "filter": filter_str,
                "interval": interval,
                "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
                "aggregation": aggregation,
            }
        )

        latencies = []
        for series in results:
            for point in series.points:
                latencies.append(point.value.double_value)

        avg_p95 = (sum(latencies) / len(latencies)) if latencies else 0.0

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "p95_latency_ms": round(avg_p95, 2),
            "samples": len(latencies)
        }

    except Exception as e:
        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "p95_latency_ms": 0.0,
            "error": str(e)
        }


def compare_baseline_to_incident(
    project_id: str,
    service_name: str,
    baseline_minutes: int = 60,
    incident_minutes: int = 15,
) -> Dict[str, Any]:
    """Compares metrics between a baseline period and an incident period to identify spikes."""
    incident_errors = get_error_rate(project_id, service_name, minutes=incident_minutes)
    baseline_errors = get_error_rate(project_id, service_name, minutes=baseline_minutes)

    incident_latency = get_request_latency(project_id, service_name, minutes=incident_minutes)
    baseline_latency = get_request_latency(project_id, service_name, minutes=baseline_minutes)

    error_spike = incident_errors.get("error_rate_percent", 0.0) > (baseline_errors.get("error_rate_percent", 0.0) + 5.0)
    latency_spike = incident_latency.get("p95_latency_ms", 0.0) > (baseline_latency.get("p95_latency_ms", 0.0) * 2.0 + 500)

    return {
        "service_name": service_name,
        "baseline_window_min": baseline_minutes,
        "incident_window_min": incident_minutes,
        "baseline": {
            "error_rate_pct": baseline_errors.get("error_rate_percent", 0.0),
            "p95_latency_ms": baseline_latency.get("p95_latency_ms", 0.0)
        },
        "incident": {
            "error_rate_pct": incident_errors.get("error_rate_percent", 0.0),
            "p95_latency_ms": incident_latency.get("p95_latency_ms", 0.0)
        },
        "anomalies_detected": {
            "error_rate_spike": error_spike,
            "latency_spike": latency_spike
        }
    }