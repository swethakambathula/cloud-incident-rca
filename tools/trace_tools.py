"""
Trace Correlation Tools for Cloud Incident RCA Agent.
Extracts and correlates Google Cloud Trace IDs across Cloud Run request logs and
application error logs to reconstruct cross-service execution flows.
"""
import re
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger("trace_tools")


def get_trace_id_from_log(log_entry: Dict[str, Any]) -> Optional[str]:
    """
    Extracts the trace ID from a Cloud Logging entry.
    Handles:
      - 'trace' field formatted as 'projects/{project_id}/traces/{trace_id}'
      - 'trace_id' attribute or json payload field
      - regex match on raw log strings or headers
    """
    if not log_entry:
        return None

    # Check direct trace_id key
    if "trace_id" in log_entry and log_entry["trace_id"] and log_entry["trace_id"] != "none":
        return str(log_entry["trace_id"])

    # Check Cloud Logging entry 'trace' property
    trace = log_entry.get("trace")
    if trace:
        return trace.split("/")[-1]

    # Check json payload
    payload = log_entry.get("payload")
    if isinstance(payload, dict):
        if payload.get("trace_id") and payload.get("trace_id") != "none":
            return str(payload["trace_id"])

    # Fallback to regex on text payload or message
    text = str(log_entry.get("text_payload") or log_entry.get("message") or "")
    match = re.search(r'\b(?:trace[-_]id[=:\s]+|traces/)([a-f0-9]{16,32}|[a-zA-Z0-9_-]{10,40})\b', text, re.I)
    if match:
        return match.group(1)

    return None


def get_trace_details(
    project_id: str,
    trace_id: str
) -> Dict[str, Any]:
    """
    Retrieves trace span details from Cloud Trace or constructs a normalized trace summary.
    """
    try:
        from google.cloud import trace_v2
        client = trace_v2.TraceServiceClient()
        name = f"projects/{project_id}/traces/{trace_id}"
        trace = client.get_trace(name=name)
        spans = []
        for span in getattr(trace, "spans", []):
            spans.append({
                "span_id": span.span_id,
                "name": span.display_name.value if getattr(span, "display_name", None) else "span",
                "start_time": span.start_time.isoformat() if getattr(span, "start_time", None) else None,
                "end_time": span.end_time.isoformat() if getattr(span, "end_time", None) else None
            })
        return {
            "trace_id": trace_id,
            "project_id": project_id,
            "spans": spans,
            "span_count": len(spans)
        }
    except Exception as e:
        logger.info(f"Direct Cloud Trace API lookup for {trace_id} not available ({e}). Using log correlation.")
        return {
            "trace_id": trace_id,
            "project_id": project_id,
            "status": "TRACE_CORRELATED_VIA_LOGS",
            "spans": []
        }


def get_related_trace_events(
    project_id: str,
    trace_id: str,
    logs: Optional[List[Dict[str, Any]]] = None
) -> List[Dict[str, Any]]:
    """
    Finds all log entries across services associated with the given trace ID.
    """
    if not logs:
        from tools.logging_tools import get_logs_by_trace
        logs = get_logs_by_trace(project_id, trace_id)

    matching = []
    for entry in logs:
        extracted = get_trace_id_from_log(entry)
        if extracted == trace_id:
            matching.append({
                "timestamp": entry.get("timestamp"),
                "service": entry.get("resource", {}).get("service_name") or entry.get("service"),
                "severity": entry.get("severity"),
                "message": entry.get("message") or str(entry.get("payload") or entry.get("text_payload"))
            })
    return matching
