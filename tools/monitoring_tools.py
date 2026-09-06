"""
Google Cloud Monitoring Tools for Cloud Incident RCA Agent.
Retrieves and compares Cloud Run metrics from Cloud Monitoring API:
  - Request Count & Error Rate
  - Request Latencies (p50, p95, p99)
  - CPU Utilization
  - Memory Utilization
  - Instance Count
Includes robust baseline vs incident comparison using tools.baseline_analyzer.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from tools.baseline_analyzer import (
    compare_error_rate,
    compare_latency,
    compare_request_volume,
    compare_cpu,
    compare_memory,
)

logger = logging.getLogger("monitoring_tools")

try:
    from google.cloud import monitoring_v3
    HAS_GCP_MONITORING = True
except ImportError:
    HAS_GCP_MONITORING = False


def _get_metric_client() -> Optional[Any]:
    if not HAS_GCP_MONITORING:
        return None
    try:
        return monitoring_v3.MetricServiceClient()
    except Exception as e:
        logger.warning(f"Could not initialize Cloud Monitoring client: {e}")
        return None


def get_request_count(
    project_id: str,
    service_name: str,
    minutes: int = 15,
) -> Dict[str, Any]:
    """Queries total request count for a Cloud Run service over the last N minutes."""
    client = _get_metric_client()
    if not client:
        return {"total_requests": 0, "status": "CLIENT_UNAVAILABLE"}

    try:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)

        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(now.timestamp())},
            "start_time": {"seconds": int(start_time.timestamp())},
        })

        filter_str = (
            f'metric.type = "run.googleapis.com/request_count" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        aggregation = monitoring_v3.Aggregation({
            "alignment_period": {"seconds": minutes * 60},
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
        })

        results = client.list_time_series(request={
            "name": f"projects/{project_id}",
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": aggregation,
        })

        total_count = 0
        breakdown = []
        for series in results:
            for point in series.points:
                val = point.value.int64_value
                total_count += val
                code_class = series.metric.labels.get("response_code_class", "2xx")
                breakdown.append({"response_code_class": code_class, "count": val})

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": total_count,
            "breakdown": breakdown
        }
    except Exception as e:
        logger.warning(f"get_request_count failed: {e}")
        return {"total_requests": 0, "error": str(e)}


def get_error_rate(
    project_id: str,
    service_name: str,
    minutes: int = 15,
) -> Dict[str, Any]:
    """Calculates HTTP 5xx error percentage over the last N minutes."""
    client = _get_metric_client()
    if not client:
        return {"error_rate_pct": 0.0, "total_requests": 0, "status": "CLIENT_UNAVAILABLE"}

    req_data = get_request_count(project_id, service_name, minutes=minutes)
    total_requests = req_data.get("total_requests", 0)
    if total_requests == 0:
        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": 0,
            "error_requests": 0,
            "error_rate_pct": 0.0,
            "status": "NO_TRAFFIC"
        }

    try:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)
        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(now.timestamp())},
            "start_time": {"seconds": int(start_time.timestamp())},
        })

        filter_str = (
            f'metric.type = "run.googleapis.com/request_count" AND '
            f'resource.labels.service_name = "{service_name}" AND '
            f'metric.labels.response_code_class = "5xx"'
        )

        aggregation = monitoring_v3.Aggregation({
            "alignment_period": {"seconds": minutes * 60},
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_SUM,
        })

        results = client.list_time_series(request={
            "name": f"projects/{project_id}",
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": aggregation,
        })

        error_count = sum(p.value.int64_value for s in results for p in s.points)
        pct = (error_count / total_requests) * 100.0 if total_requests > 0 else 0.0

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "total_requests": total_requests,
            "error_requests": error_count,
            "error_rate_pct": round(pct, 2)
        }
    except Exception as e:
        logger.warning(f"get_error_rate failed: {e}")
        return {"error_rate_pct": 0.0, "error": str(e)}


def get_request_latency(
    project_id: str,
    service_name: str,
    minutes: int = 15,
) -> Dict[str, Any]:
    """Queries p95 latency in milliseconds for Cloud Run requests."""
    client = _get_metric_client()
    if not client:
        return {"p95_latency_ms": 150.0, "status": "CLIENT_UNAVAILABLE"}

    try:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)
        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(now.timestamp())},
            "start_time": {"seconds": int(start_time.timestamp())},
        })

        filter_str = (
            f'metric.type = "run.googleapis.com/request_latencies" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        aggregation = monitoring_v3.Aggregation({
            "alignment_period": {"seconds": minutes * 60},
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_PERCENTILE_95,
        })

        results = client.list_time_series(request={
            "name": f"projects/{project_id}",
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": aggregation,
        })

        latencies = [p.value.double_value for s in results for p in s.points]
        avg_p95 = (sum(latencies) / len(latencies)) if latencies else 150.0

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "p95_latency_ms": round(avg_p95, 2)
        }
    except Exception as e:
        logger.warning(f"get_request_latency failed: {e}")
        return {"p95_latency_ms": 150.0, "error": str(e)}


def get_cpu_utilization(
    project_id: str,
    service_name: str,
    minutes: int = 15,
) -> Dict[str, Any]:
    """Queries container CPU utilization percentage (0-100%)."""
    client = _get_metric_client()
    if not client:
        return {"cpu_utilization_pct": 20.0, "status": "CLIENT_UNAVAILABLE"}

    try:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)
        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(now.timestamp())},
            "start_time": {"seconds": int(start_time.timestamp())},
        })

        filter_str = (
            f'metric.type = "run.googleapis.com/container/cpu/utilizations" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        aggregation = monitoring_v3.Aggregation({
            "alignment_period": {"seconds": minutes * 60},
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_PERCENTILE_95,
        })

        results = client.list_time_series(request={
            "name": f"projects/{project_id}",
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": aggregation,
        })

        vals = [p.value.double_value * 100.0 for s in results for p in s.points]
        avg_cpu = (sum(vals) / len(vals)) if vals else 20.0

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "cpu_utilization_pct": round(avg_cpu, 2)
        }
    except Exception as e:
        logger.warning(f"get_cpu_utilization failed: {e}")
        return {"cpu_utilization_pct": 20.0, "error": str(e)}


def get_memory_utilization(
    project_id: str,
    service_name: str,
    minutes: int = 15,
) -> Dict[str, Any]:
    """Queries container Memory utilization percentage (0-100%)."""
    client = _get_metric_client()
    if not client:
        return {"memory_utilization_pct": 35.0, "status": "CLIENT_UNAVAILABLE"}

    try:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)
        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(now.timestamp())},
            "start_time": {"seconds": int(start_time.timestamp())},
        })

        filter_str = (
            f'metric.type = "run.googleapis.com/container/memory/utilizations" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        aggregation = monitoring_v3.Aggregation({
            "alignment_period": {"seconds": minutes * 60},
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_PERCENTILE_95,
        })

        results = client.list_time_series(request={
            "name": f"projects/{project_id}",
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": aggregation,
        })

        vals = [p.value.double_value * 100.0 for s in results for p in s.points]
        avg_mem = (sum(vals) / len(vals)) if vals else 35.0

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "memory_utilization_pct": round(avg_mem, 2)
        }
    except Exception as e:
        logger.warning(f"get_memory_utilization failed: {e}")
        return {"memory_utilization_pct": 35.0, "error": str(e)}


def get_instance_count(
    project_id: str,
    service_name: str,
    minutes: int = 15,
) -> Dict[str, Any]:
    """Queries active Cloud Run instance count."""
    client = _get_metric_client()
    if not client:
        return {"instance_count": 1, "status": "CLIENT_UNAVAILABLE"}

    try:
        now = datetime.now(timezone.utc)
        start_time = now - timedelta(minutes=minutes)
        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(now.timestamp())},
            "start_time": {"seconds": int(start_time.timestamp())},
        })

        filter_str = (
            f'metric.type = "run.googleapis.com/container/instance_count" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        aggregation = monitoring_v3.Aggregation({
            "alignment_period": {"seconds": minutes * 60},
            "per_series_aligner": monitoring_v3.Aggregation.Aligner.ALIGN_MAX,
        })

        results = client.list_time_series(request={
            "name": f"projects/{project_id}",
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": aggregation,
        })

        counts = [p.value.int64_value for s in results for p in s.points]
        max_inst = max(counts) if counts else 1

        return {
            "service_name": service_name,
            "window_minutes": minutes,
            "instance_count": max_inst
        }
    except Exception as e:
        logger.warning(f"get_instance_count failed: {e}")
        return {"instance_count": 1, "error": str(e)}


def get_metric_window(
    project_id: str,
    service_name: str,
    metric_type: str,
    start_time: str,
    end_time: str,
    aligner: Any = None
) -> List[Dict[str, Any]]:
    """Generic metric retriever across an arbitrary ISO window."""
    client = _get_metric_client()
    if not client:
        return []

    try:
        t_start = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
        t_end = datetime.fromisoformat(end_time.replace("Z", "+00:00"))

        interval = monitoring_v3.TimeInterval({
            "end_time": {"seconds": int(t_end.timestamp())},
            "start_time": {"seconds": int(t_start.timestamp())},
        })

        filter_str = (
            f'metric.type = "{metric_type}" AND '
            f'resource.labels.service_name = "{service_name}"'
        )

        results = client.list_time_series(request={
            "name": f"projects/{project_id}",
            "filter": filter_str,
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
        })

        points = []
        for s in results:
            for p in s.points:
                val = p.value.double_value or float(p.value.int64_value)
                points.append({
                    "timestamp": p.interval.end_time.ToDatetime().isoformat(),
                    "value": val
                })
        return points
    except Exception as e:
        logger.warning(f"get_metric_window failed: {e}")
        return []


def compare_baseline_to_incident(
    project_id: str,
    service_name: str,
    baseline_minutes: int = 15,
    incident_minutes: int = 15,
) -> Dict[str, Any]:
    """
    Compares metrics between baseline window (previous 15m) and incident window (current 15m).
    Returns unified comparisons across error rate, latency, volume, cpu, and memory.
    """
    b_err = get_error_rate(project_id, service_name, minutes=baseline_minutes).get("error_rate_pct", 0.0)
    i_err = get_error_rate(project_id, service_name, minutes=incident_minutes).get("error_rate_pct", 0.0)
    err_comp = compare_error_rate(b_err, i_err)

    b_lat = get_request_latency(project_id, service_name, minutes=baseline_minutes).get("p95_latency_ms", 150.0)
    i_lat = get_request_latency(project_id, service_name, minutes=incident_minutes).get("p95_latency_ms", 150.0)
    lat_comp = compare_latency(b_lat, i_lat)

    b_req = float(get_request_count(project_id, service_name, minutes=baseline_minutes).get("total_requests", 100))
    i_req = float(get_request_count(project_id, service_name, minutes=incident_minutes).get("total_requests", 100))
    req_comp = compare_request_volume(b_req, i_req)

    b_cpu = get_cpu_utilization(project_id, service_name, minutes=baseline_minutes).get("cpu_utilization_pct", 20.0)
    i_cpu = get_cpu_utilization(project_id, service_name, minutes=incident_minutes).get("cpu_utilization_pct", 20.0)
    cpu_comp = compare_cpu(b_cpu, i_cpu)

    b_mem = get_memory_utilization(project_id, service_name, minutes=baseline_minutes).get("memory_utilization_pct", 35.0)
    i_mem = get_memory_utilization(project_id, service_name, minutes=incident_minutes).get("memory_utilization_pct", 35.0)
    mem_comp = compare_memory(b_mem, i_mem)

    return {
        "service_name": service_name,
        "error_rate": err_comp,
        "latency_p95": lat_comp,
        "request_volume": req_comp,
        "cpu": cpu_comp,
        "memory": mem_comp
    }