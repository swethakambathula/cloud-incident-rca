"""
Google Cloud Logging Tools for Cloud Incident RCA Agent.
Retrieves and normalizes request logs and structured application logs from Cloud Run.
Includes graceful error handling and offline/mock fallbacks.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger("logging_tools")

try:
    from google.cloud import logging_v2
    HAS_GCP_LOGGING = True
except ImportError:
    HAS_GCP_LOGGING = False


def _get_client(project_id: str) -> Optional[Any]:
    if not HAS_GCP_LOGGING:
        return None
    try:
        return logging_v2.Client(project=project_id)
    except Exception as e:
        logger.warning(f"Failed to initialize Cloud Logging client for {project_id}: {e}")
        return None


def _normalize_entry(entry: Any) -> Dict[str, Any]:
    """Extracts standard dictionary fields from a Cloud Logging Entry."""
    timestamp = entry.timestamp.isoformat() if getattr(entry, "timestamp", None) else None
    severity = getattr(entry, "severity", "DEFAULT")
    payload = getattr(entry, "payload", None)
    text_payload = getattr(entry, "text_payload", None)
    http_request = getattr(entry, "http_request", None)
    trace = getattr(entry, "trace", None)
    span_id = getattr(entry, "span_id", None)
    resource = dict(getattr(entry.resource, "labels", {})) if getattr(entry, "resource", None) else {}

    trace_id = trace.split("/")[-1] if trace and "/" in trace else trace

    return {
        "timestamp": timestamp,
        "severity": severity,
        "payload": payload,
        "text_payload": text_payload,
        "http_request": dict(http_request) if http_request else None,
        "trace_id": trace_id,
        "span_id": span_id,
        "resource": resource
    }


def get_service_logs(
    project_id: str,
    service_name: str,
    limit: int = 50,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Fetches recent logs for a Cloud Run service."""
    client = _get_client(project_id)
    if not client:
        return []

    log_filter = (
        f'resource.type="cloud_run_revision" AND '
        f'resource.labels.service_name="{service_name}"'
    )
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=limit,
            timeout=timeout
        )
        return [_normalize_entry(e) for e in entries]
    except Exception as e:
        logger.warning(f"get_service_logs failed: {e}")
        return []


def get_error_logs(
    project_id: str,
    service_name: str,
    limit: int = 50,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Fetches ERROR, CRITICAL, and FATAL logs for a Cloud Run service."""
    client = _get_client(project_id)
    if not client:
        return []

    log_filter = (
        f'resource.type="cloud_run_revision" AND '
        f'resource.labels.service_name="{service_name}" AND '
        f'severity>=ERROR'
    )
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=limit,
            timeout=timeout
        )
        return [_normalize_entry(e) for e in entries]
    except Exception as e:
        logger.warning(f"get_error_logs failed: {e}")
        return []


def get_logs_for_time_window(
    project_id: str,
    service_name: str,
    start_time: str,
    end_time: str,
    limit: int = 200,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Fetches all logs within a specified ISO timestamp window."""
    client = _get_client(project_id)
    if not client:
        return []

    log_filter = (
        f'resource.type="cloud_run_revision" AND '
        f'resource.labels.service_name="{service_name}" AND '
        f'timestamp>="{start_time}" AND timestamp<="{end_time}"'
    )
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=limit,
            timeout=timeout
        )
        return [_normalize_entry(e) for e in entries]
    except Exception as e:
        logger.warning(f"get_logs_for_time_window failed: {e}")
        return []


def get_logs_for_revision(
    project_id: str,
    revision_name: str,
    limit: int = 50,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Fetches logs isolated to a specific Cloud Run revision."""
    client = _get_client(project_id)
    if not client:
        return []

    log_filter = (
        f'resource.type="cloud_run_revision" AND '
        f'resource.labels.revision_name="{revision_name}"'
    )
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=limit,
            timeout=timeout
        )
        return [_normalize_entry(e) for e in entries]
    except Exception as e:
        logger.warning(f"get_logs_for_revision failed: {e}")
        return []


def get_request_logs(
    project_id: str,
    service_name: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Fetches Cloud Run HTTP access/request logs (run.googleapis.com/requests)."""
    client = _get_client(project_id)
    if not client:
        return []

    time_clause = f'AND timestamp>="{start_time}" AND timestamp<="{end_time}" ' if start_time and end_time else ""
    log_filter = (
        f'resource.type="cloud_run_revision" AND '
        f'resource.labels.service_name="{service_name}" AND '
        f'logName=~"run.googleapis.com%2Frequests" {time_clause}'
    )
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=limit,
            timeout=timeout
        )
        return [_normalize_entry(e) for e in entries]
    except Exception as e:
        logger.warning(f"get_request_logs failed: {e}")
        return []


def get_application_logs(
    project_id: str,
    service_name: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    limit: int = 100,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Fetches application stdout/stderr logs (excluding ingress request logs)."""
    client = _get_client(project_id)
    if not client:
        return []

    time_clause = f'AND timestamp>="{start_time}" AND timestamp<="{end_time}" ' if start_time and end_time else ""
    log_filter = (
        f'resource.type="cloud_run_revision" AND '
        f'resource.labels.service_name="{service_name}" AND '
        f'NOT logName=~"run.googleapis.com%2Frequests" {time_clause}'
    )
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=limit,
            timeout=timeout
        )
        return [_normalize_entry(e) for e in entries]
    except Exception as e:
        logger.warning(f"get_application_logs failed: {e}")
        return []


def get_logs_by_trace(
    project_id: str,
    trace_id: str,
    limit: int = 50,
    timeout: float = 5.0
) -> List[Dict[str, Any]]:
    """Fetches all logs matching a specific trace ID across services."""
    client = _get_client(project_id)
    if not client:
        return []

    log_filter = f'trace=~"{trace_id}"'
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.DESCENDING,
            max_results=limit,
            timeout=timeout
        )
        return [_normalize_entry(e) for e in entries]
    except Exception as e:
        logger.warning(f"get_logs_by_trace failed: {e}")
        return []


def get_error_frequency(
    project_id: str,
    service_name: str,
    start_time: str,
    end_time: str
) -> Dict[str, int]:
    """Returns a dictionary of error codes / types and their occurrence frequencies."""
    logs = get_error_logs(project_id, service_name, limit=200)
    freq: Dict[str, int] = {}

    for l in logs:
        payload = l.get("payload")
        if isinstance(payload, dict) and "error_code" in payload:
            code = payload["error_code"]
            freq[code] = freq.get(code, 0) + 1
        elif isinstance(payload, dict) and "incident_type" in payload:
            code = payload["incident_type"]
            freq[code] = freq.get(code, 0) + 1
        else:
            text = str(payload or l.get("text_payload") or "UNKNOWN_ERROR")
            first_word = text.split(":")[0].split(" ")[0][:40]
            freq[first_word] = freq.get(first_word, 0) + 1

    return freq


def find_first_error_occurrence(
    project_id: str,
    service_name: str,
    start_time: str,
    end_time: str
) -> Optional[Dict[str, Any]]:
    """Identifies the earliest error log entry in the time window (incident onset)."""
    client = _get_client(project_id)
    if not client:
        return None

    log_filter = (
        f'resource.type="cloud_run_revision" AND '
        f'resource.labels.service_name="{service_name}" AND '
        f'severity>=ERROR AND '
        f'timestamp>="{start_time}" AND timestamp<="{end_time}"'
    )
    try:
        entries = client.list_entries(
            filter_=log_filter,
            order_by=logging_v2.ASCENDING,
            max_results=1
        )
        first_list = [_normalize_entry(e) for e in entries]
        return first_list[0] if first_list else None
    except Exception as e:
        logger.warning(f"find_first_error_occurrence failed: {e}")
        return None