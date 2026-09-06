"""
Local Evidence Normalizer.
Transforms raw Google Cloud logs, metrics, deployment revisions, and trace telemetry
into a structured, sanitized IncidentEvidence object.
Ensures raw Google Cloud JSON payloads are never directly passed to LLMs.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from schemas.evidence import IncidentEvidence
from tools.baseline_analyzer import (
    compare_error_rate,
    compare_latency,
    compare_request_volume,
    compare_cpu,
    compare_memory,
)
from tools.severity import classify_incident_severity
from tools.blast_radius import detect_blast_radius


def normalize_evidence(
    incident_id: str,
    project_id: str,
    service_name: str,
    start_time: str,
    end_time: str,
    raw_logs: Optional[List[Dict[str, Any]]] = None,
    raw_metrics: Optional[Dict[str, Any]] = None,
    deployment_events: Optional[List[Dict[str, Any]]] = None,
    raw_traces: Optional[List[Dict[str, Any]]] = None,
    dependencies: Optional[List[Dict[str, Any]]] = None,
    revision_name: Optional[str] = None,
    region: Optional[str] = "us-central1"
) -> IncidentEvidence:
    """
    Normalizes multi-modal cloud signals into an IncidentEvidence schema.
    """
    raw_logs = raw_logs or []
    raw_metrics = raw_metrics or {}
    deployment_events = deployment_events or []
    raw_traces = raw_traces or []
    dependencies = dependencies or []

    # 1. Parse and categorize logs
    application_errors: List[Dict[str, Any]] = []
    request_errors: List[Dict[str, Any]] = []
    symptoms: List[str] = []
    affected_endpoints: List[str] = []
    app_error_counts: Dict[str, int] = {}

    for log in raw_logs:
        payload = log.get("payload") or {}
        text = log.get("text_payload") or ""
        msg = ""

        if isinstance(payload, dict):
            error_code = payload.get("error_code") or payload.get("incident_type")
            msg = payload.get("message") or str(payload)
            endpoint = payload.get("endpoint") or payload.get("path")
            if endpoint and endpoint not in affected_endpoints:
                affected_endpoints.append(endpoint)

            if error_code:
                app_error_counts[error_code] = app_error_counts.get(error_code, 0) + 1
        elif isinstance(payload, str):
            msg = payload
        elif text:
            msg = text

        # Check for HTTP request errors
        http_req = log.get("http_request") or {}
        status = http_req.get("status") or log.get("status")
        req_url = http_req.get("request_url") or log.get("url") or ""
        if status and int(status) >= 400:
            endpoint = req_url.split("?")[0] if req_url else "/unknown"
            if endpoint and endpoint not in affected_endpoints:
                affected_endpoints.append(endpoint)
            request_errors.append({
                "status_code": int(status),
                "endpoint": endpoint,
                "timestamp": log.get("timestamp")
            })

    # Summarize application error types
    for err_code, count in app_error_counts.items():
        application_errors.append({
            "error_code": err_code,
            "count": count
        })
        symptoms.append(f"Application error '{err_code}' occurred {count} times.")

    if request_errors:
        symptoms.append(f"Recorded {len(request_errors)} HTTP 4xx/5xx request failures.")

    # 2. Normalize and compare metrics
    baseline_metrics = raw_metrics.get("baseline", {})
    incident_metrics = raw_metrics.get("incident", {})

    b_err = float(baseline_metrics.get("error_rate_pct", 0.0))
    i_err = float(incident_metrics.get("error_rate_pct", 0.0))
    err_comparison = compare_error_rate(b_err, i_err)

    b_lat = float(baseline_metrics.get("latency_p95_ms", 150.0))
    i_lat = float(incident_metrics.get("latency_p95_ms", 150.0))
    lat_comparison = compare_latency(b_lat, i_lat)

    b_rpm = float(baseline_metrics.get("request_count", 500.0))
    i_rpm = float(incident_metrics.get("request_count", 500.0))
    req_comparison = compare_request_volume(b_rpm, i_rpm)

    b_cpu = float(baseline_metrics.get("cpu_utilization_pct", 20.0))
    i_cpu = float(incident_metrics.get("cpu_utilization_pct", 20.0))
    cpu_comparison = compare_cpu(b_cpu, i_cpu)

    b_mem = float(baseline_metrics.get("memory_utilization_pct", 35.0))
    i_mem = float(incident_metrics.get("memory_utilization_pct", 35.0))
    mem_comparison = compare_memory(b_mem, i_mem)

    # Add metric symptoms
    if err_comparison["severity"] in ["WARNING", "CRITICAL"]:
        symptoms.append(f"HTTP error rate increased to {err_comparison['incident']}% ({err_comparison['severity']}).")
    if lat_comparison["severity"] in ["WARNING", "CRITICAL"]:
        symptoms.append(f"P95 latency elevated to {lat_comparison['incident']}ms ({lat_comparison['severity']}).")
    if cpu_comparison["severity"] in ["WARNING", "CRITICAL"]:
        symptoms.append(f"CPU utilization spiked to {cpu_comparison['incident']}% ({cpu_comparison['severity']}).")
    if mem_comparison["severity"] in ["WARNING", "CRITICAL"]:
        symptoms.append(f"Memory utilization spiked to {mem_comparison['incident']}% ({mem_comparison['severity']}).")
    if req_comparison["severity"] in ["WARNING", "CRITICAL"]:
        symptoms.append(f"Request volume changed by {req_comparison['percentage_change']}% ({req_comparison['severity']}).")

    # 3. Classify severity
    dep_broken = any(d.get("status") in ["UNREACHABLE", "UNAVAILABLE", "ERROR"] for d in dependencies)
    severity = classify_incident_severity(
        error_rate_pct=err_comparison["incident"],
        latency_p95_ms=lat_comparison["incident"],
        affected_endpoints=affected_endpoints,
        is_downstream_broken=dep_broken
    )

    # 4. Blast radius
    dep_names = [d["name"] for d in dependencies if d.get("status") != "HEALTHY" and "name" in d]
    active_rev = revision_name or (deployment_events[0].get("revision_name") if deployment_events else None)
    blast_radius = detect_blast_radius(
        service_name=service_name,
        revision_name=active_rev,
        region=region,
        affected_endpoints=affected_endpoints,
        dependencies_affected=dep_names
    )

    # 5. Sanitize and package raw evidence
    raw_evidence_items: List[Dict[str, Any]] = []
    for log in raw_logs[:15]:
        raw_evidence_items.append({
            "source": "cloud_logging",
            "timestamp": log.get("timestamp"),
            "severity": log.get("severity", "INFO"),
            "summary": str(log.get("payload") or log.get("text_payload") or "")[:200]
        })

    return IncidentEvidence(
        incident_id=incident_id,
        start_time=start_time,
        end_time=end_time,
        project_id=project_id,
        service_name=service_name,
        revision_name=active_rev,
        region=region,
        severity=severity,
        symptoms=symptoms if symptoms else ["Minor or localized telemetry perturbation"],
        application_errors=application_errors,
        request_errors=request_errors[:30],
        latency=lat_comparison,
        request_count=req_comparison,
        cpu_utilization=cpu_comparison,
        memory_utilization=mem_comparison,
        recent_deployments=deployment_events,
        dependencies=dependencies,
        traces=raw_traces,
        blast_radius=blast_radius,
        raw_evidence=raw_evidence_items
    )
