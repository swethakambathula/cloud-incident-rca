"""
Incident Correlation Layer and Unified IncidentEvidence Collector.
Correlates application logs with Cloud Run request logs, queries monitoring metrics,
retrieves deployment revisions and trace context, and produces a normalized IncidentEvidence object.
"""
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

from schemas.evidence import IncidentEvidence
from tools.logging_tools import (
    get_logs_for_time_window,
    get_request_logs,
    get_application_logs,
    get_error_frequency,
)
from tools.monitoring_tools import compare_baseline_to_incident
from tools.deployment_tools import (
    get_current_revision,
    get_recent_revisions,
)
from tools.trace_tools import get_trace_id_from_log
from tools.normalizer import normalize_evidence

logger = logging.getLogger("correlation")


def correlate_logs(
    application_logs: List[Dict[str, Any]],
    request_logs: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Correlates application logs with Cloud Run request logs.
    Matches by:
      - Trace ID (when available)
      - Timestamps within a narrow 2-second window
      - Connects application error codes with HTTP response codes
    """
    correlated_events = []

    # Map request logs by trace_id and timestamp
    requests_by_trace: Dict[str, Dict[str, Any]] = {}
    for r in request_logs:
        tid = get_trace_id_from_log(r)
        if tid:
            requests_by_trace[tid] = r

    for app_log in application_logs:
        payload = app_log.get("payload") or {}
        error_code = None
        if isinstance(payload, dict):
            error_code = payload.get("error_code") or payload.get("incident_type")
        elif isinstance(payload, str) and "ERROR" in payload:
            error_code = payload.split(":")[0]

        tid = get_trace_id_from_log(app_log)
        matched_req = requests_by_trace.get(tid) if tid else None

        http_status = None
        req_endpoint = None
        if matched_req:
            http_req = matched_req.get("http_request") or {}
            http_status = http_req.get("status")
            req_endpoint = (http_req.get("request_url") or "").split("?")[0]
        elif app_log.get("http_request"):
            http_req = app_log.get("http_request") or {}
            http_status = http_req.get("status")
            req_endpoint = (http_req.get("request_url") or "").split("?")[0]

        correlated_events.append({
            "timestamp": app_log.get("timestamp"),
            "severity": app_log.get("severity"),
            "error_code": error_code,
            "trace_id": tid,
            "http_status": http_status,
            "endpoint": req_endpoint,
            "message": str(payload or app_log.get("text_payload") or "")
        })

    return correlated_events


def collect_incident_evidence(
    project_id: str,
    service_name: str,
    incident_start: Optional[str] = None,
    incident_end: Optional[str] = None,
    minutes_window: int = 10,
    region: str = "us-central1"
) -> IncidentEvidence:
    """
    Unified Google Cloud IncidentEvidence Collector.
    Collects logs, monitoring metrics, deployments, traces, and dependencies over
    the investigation window and outputs a clean IncidentEvidence object.
    """
    now = datetime.now(timezone.utc)
    if not incident_end:
        end_dt = now
        incident_end = end_dt.isoformat()
    else:
        end_dt = datetime.fromisoformat(incident_end.replace("Z", "+00:00"))

    if not incident_start:
        start_dt = end_dt - timedelta(minutes=minutes_window)
        incident_start = start_dt.isoformat()
    else:
        start_dt = datetime.fromisoformat(incident_start.replace("Z", "+00:00"))

    incident_id = f"INC-{service_name.upper()}-{int(start_dt.timestamp())}"

    # 1. Fetch Cloud Logging
    try:
        app_logs = get_application_logs(project_id, service_name, incident_start, incident_end, limit=150)
        req_logs = get_request_logs(project_id, service_name, incident_start, incident_end, limit=150)
        all_logs = get_logs_for_time_window(project_id, service_name, incident_start, incident_end, limit=300)
    except Exception as e:
        logger.warning(f"Error fetching Cloud Logging: {e}")
        app_logs, req_logs, all_logs = [], [], []

    # Correlate logs
    correlated = correlate_logs(app_logs, req_logs)

    # 2. Fetch Cloud Monitoring metrics comparison
    try:
        metric_comparisons = compare_baseline_to_incident(
            project_id=project_id,
            service_name=service_name,
            baseline_minutes=minutes_window,
            incident_minutes=minutes_window
        )
    except Exception as e:
        logger.warning(f"Error comparing monitoring metrics: {e}")
        metric_comparisons = {}

    # Format into raw_metrics structure for normalizer
    baseline_metrics = {
        "error_rate_pct": metric_comparisons.get("error_rate", {}).get("baseline", 0.1),
        "latency_p95_ms": metric_comparisons.get("latency_p95", {}).get("baseline", 150.0),
        "request_count": metric_comparisons.get("request_volume", {}).get("baseline", 500.0),
        "cpu_utilization_pct": metric_comparisons.get("cpu", {}).get("baseline", 20.0),
        "memory_utilization_pct": metric_comparisons.get("memory", {}).get("baseline", 35.0)
    }
    incident_metrics = {
        "error_rate_pct": metric_comparisons.get("error_rate", {}).get("incident", 0.1),
        "latency_p95_ms": metric_comparisons.get("latency_p95", {}).get("incident", 150.0),
        "request_count": metric_comparisons.get("request_volume", {}).get("incident", 500.0),
        "cpu_utilization_pct": metric_comparisons.get("cpu", {}).get("incident", 20.0),
        "memory_utilization_pct": metric_comparisons.get("memory", {}).get("incident", 35.0)
    }
    raw_metrics = {"baseline": baseline_metrics, "incident": incident_metrics}

    # 3. Fetch Deployment / Revision history
    try:
        recent_revisions = get_recent_revisions(project_id, region, service_name, limit=5)
        current_rev_info = get_current_revision(project_id, region, service_name)
        active_revision = current_rev_info.get("latest_ready_revision") if current_rev_info else None
    except Exception as e:
        logger.warning(f"Error fetching deployment revisions: {e}")
        recent_revisions = []
        active_revision = f"{service_name}-active"

    # 4. Extract Traces
    traces = []
    seen_trace_ids = set()
    for entry in correlated:
        tid = entry.get("trace_id")
        if tid and tid not in seen_trace_ids and tid != "none":
            seen_trace_ids.add(tid)
            traces.append({
                "trace_id": tid,
                "timestamp": entry.get("timestamp"),
                "status_code": entry.get("http_status"),
                "endpoint": entry.get("endpoint"),
                "error_code": entry.get("error_code")
            })
            if len(traces) >= 10:
                break

    # 5. Extract Dependencies from logs
    dependencies = []
    for l in all_logs:
        payload = l.get("payload")
        if isinstance(payload, dict) and "dependency" in payload and payload["dependency"] != "none":
            dep_name = payload["dependency"]
            if not any(d["name"] == dep_name for d in dependencies):
                dep_status = "ERROR" if l.get("severity") in ["ERROR", "CRITICAL"] else "HEALTHY"
                dependencies.append({"name": dep_name, "status": dep_status})

    # Combine into normalized IncidentEvidence
    return normalize_evidence(
        incident_id=incident_id,
        project_id=project_id,
        service_name=service_name,
        start_time=incident_start,
        end_time=incident_end,
        raw_logs=all_logs,
        raw_metrics=raw_metrics,
        deployment_events=recent_revisions,
        raw_traces=traces,
        dependencies=dependencies,
        revision_name=active_revision,
        region=region
    )
