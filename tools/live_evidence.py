"""
Live evidence bridge (Part 4): derive IncidentEvidence from streamed live logs.

Two paths:
- merge_static_with_live(): static scenario JSON provides deployments, traces,
  dependencies, baselines; log-derived counts, rates and latencies are
  recomputed from the actual live log stream.
- build_evidence_from_logs(): scenarios with no static file get a full
  evidence object built purely from live logs + scenario spec (honest
  unknown/weak RCA when signals are inconclusive).
"""
from collections import Counter
from typing import List, Dict, Any
from tools.live_log_generator import _p95, SCENARIO_SPECS
from tools.normalizer import normalize_evidence


def derive_log_stats(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = len(logs) or 1
    err_logs = [l for l in logs if l.get("severity") in ("ERROR", "CRITICAL")]
    codes = Counter(l.get("error_code") for l in err_logs if l.get("error_code"))
    status_counter = Counter()
    endpoint_status = Counter()
    for l in logs:
        try:
            sc = int(l.get("status_code", 200))
        except (TypeError, ValueError):
            sc = 200
        status_counter[sc] += 1
        endpoint_status[(l.get("endpoint", "/unknown"), sc)] += 1
    n5xx = sum(c for s, c in status_counter.items() if 500 <= s <= 599)
    lats = [float(l.get("latency_ms", 0)) for l in logs]
    cpus = [float(l.get("cpu_percent", 0)) for l in logs]
    mems = [float(l.get("memory_percent", 0)) for l in logs]
    return {
        "total": len(logs),
        "error_rate_pct": round(100 * n5xx / total, 1),
        "p95_ms": _p95(lats),
        "avg_cpu": round(sum(cpus) / len(cpus), 1) if cpus else 0.0,
        "avg_mem": round(sum(mems) / len(mems), 1) if mems else 0.0,
        "error_counts": dict(codes),
        "request_errors": [
            {"endpoint": ep, "status_code": sc, "count": n}
            for (ep, sc), n in endpoint_status.most_common() if sc >= 400
        ],
        "application_errors": [
            {"error_code": code, "count": n} for code, n in codes.most_common()
        ],
        "endpoints": sorted({l.get("endpoint", "/unknown") for l in logs}),
        "trace_ids": [l.get("trace_id") for l in logs if l.get("trace_id")][:10],
    }


def merge_static_with_live(static_dict: Dict[str, Any], live_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Override log-derived fields of a static incident dict with live stream stats."""
    if not live_logs:
        return static_dict
    stats = derive_log_stats(live_logs)
    merged = dict(static_dict)
    merged["application_errors"] = stats["application_errors"] or merged.get("application_errors", [])
    merged["request_errors"] = stats["request_errors"] or merged.get("request_errors", [])

    def _with_incident(metric: Dict[str, Any], incident_value: float, incident_key_candidates) -> Dict[str, Any]:
        m = dict(metric or {})
        for key in incident_key_candidates:
            if key in m:
                m[key] = incident_value
        if "incident" in m:
            m["incident"] = incident_value
        return m

    merged["latency"] = _with_incident(merged.get("latency", {}), stats["p95_ms"],
                                       ["incident_p95_ms", "incident"])
    rc = dict(merged.get("request_count", {}))
    if "error_rate_pct" in rc:
        rc["error_rate_pct"] = stats["error_rate_pct"]
    merged["request_count"] = rc
    merged["cpu_utilization"] = _with_incident(merged.get("cpu_utilization", {}), stats["avg_cpu"],
                                              ["incident_pct", "incident"])
    merged["memory_utilization"] = _with_incident(merged.get("memory_utilization", {}), stats["avg_mem"],
                                                 ["incident_pct", "incident"])
    merged["raw_evidence"] = [
        {"timestamp": l.get("timestamp"), "source": "logging",
         "log": f"{l.get('severity')}: {l.get('error_code','')} {l.get('message','')}"[:200]}
        for l in live_logs if l.get("severity") in ("ERROR", "CRITICAL", "WARNING")
    ][:15]
    merged.setdefault("symptoms", []).append(
        f"Live stream: {stats['total']} requests, {stats['error_rate_pct']}% 5xx, p95 {stats['p95_ms']}ms."
    )
    return merged


def build_evidence_from_logs(scenario: str, logs: List[Dict[str, Any]],
                             project_id: str = "cloud-incident-prod",
                             region: str = "us-central1"):
    """Full IncidentEvidence from live logs only (scenarios without static files)."""
    from schemas.evidence import IncidentEvidence
    spec = SCENARIO_SPECS[scenario]
    stats = derive_log_stats(logs)
    timestamps = sorted(l.get("timestamp", "") for l in logs if l.get("timestamp"))
    start = timestamps[0] if timestamps else "2026-09-05T14:00:00Z"
    end = timestamps[-1] if timestamps else "2026-09-05T14:15:00Z"
    incident_id = (logs[0].get("incident_id") if logs else None) or f"INC-LIVE-{spec['incident_type']}"

    raw_logs = [{
        "timestamp": l.get("timestamp"),
        "severity": l.get("severity", "INFO"),
        "payload": {"error_code": l.get("error_code"), "message": l.get("message"),
                    "endpoint": l.get("endpoint")},
        "http_request": {"status": l.get("status_code", 200), "request_url": l.get("endpoint", "/")},
        "trace_id": l.get("trace_id"),
    } for l in logs]
    raw_metrics = {
        "baseline": {"error_rate_pct": 0.4, "latency_p95_ms": 160.0, "request_count": 550.0,
                     "cpu_utilization_pct": 21.0, "memory_utilization_pct": 36.0},
        "incident": {"error_rate_pct": stats["error_rate_pct"], "latency_p95_ms": stats["p95_ms"],
                     "request_count": float(stats["total"]),
                     "cpu_utilization_pct": stats["avg_cpu"], "memory_utilization_pct": stats["avg_mem"]},
    }
    dep = spec["dependency"]
    dependencies = ([{"name": dep, "status": "DEGRADED", "type": "http_service"}]
                    if dep not in ("none", "") else [])
    traces = ([{"trace_id": tid, "root_span": spec["endpoint"], "duration_ms": spec["latency_ms"],
                "downstream_status": spec["status_code"]} for tid in stats["trace_ids"][:5]]
              if dep not in ("none", "") else
              [{"trace_id": tid, "root_span": spec["endpoint"], "duration_ms": spec["latency_ms"]}
               for tid in stats["trace_ids"][:5]])
    return normalize_evidence(
        incident_id=incident_id, project_id=project_id, service_name=spec["service"],
        start_time=start, end_time=end, raw_logs=raw_logs, raw_metrics=raw_metrics,
        deployment_events=[], raw_traces=traces, dependencies=dependencies,
        revision_name=logs[-1].get("revision") if logs else None, region=region,
    )
