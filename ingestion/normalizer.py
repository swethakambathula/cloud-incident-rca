"""Normalize parsed records into NormalizedLogRecord dicts.

Missing fields stay None. Aggregates (services, time range, error counts)
feed the ingestion preview and the file-based RCA evidence builder.
"""
from collections import Counter
from typing import Any, Dict, List

from ingestion.field_mapper import map_record
from ingestion.timestamp_parser import extract_timestamp, parse_timestamp

NORMALIZED_FIELDS = (
    "timestamp", "severity", "source", "service_name", "component", "host",
    "revision", "environment", "incident_id", "request_id", "trace_id",
    "span_id", "endpoint", "method", "status_code", "latency_ms",
    "error_code", "message", "dependency", "region", "raw_line", "metadata",
)


def normalize(records: List[Dict[str, Any]], default_source: str = "upload",
              default_service: str = "") -> List[Dict[str, Any]]:
    out = []
    for raw in records:
        mapped = map_record(raw)
        rec: Dict[str, Any] = {f: mapped.get(f) for f in NORMALIZED_FIELDS}
        rec["metadata"] = mapped.get("metadata") or {}
        if not rec["timestamp"]:
            rec["timestamp"] = extract_timestamp(str(raw.get("raw_line") or raw.get("message") or ""))
        else:
            rec["timestamp"] = parse_timestamp(rec["timestamp"])
        if not rec["severity"]:
            sc = rec["status_code"]
            try:
                sc = int(sc) if sc is not None else 200
            except (TypeError, ValueError):
                sc = 200
            rec["severity"] = "ERROR" if sc >= 500 else ("WARNING" if sc >= 400 else "INFO")
        if not rec["source"]:
            rec["source"] = default_source
        if not rec["service_name"] and default_service:
            rec["service_name"] = default_service
        if raw.get("raw_line") and not rec.get("raw_line"):
            rec["raw_line"] = raw["raw_line"][:500]
        if not rec["message"] and rec["raw_line"]:
            rec["message"] = rec["raw_line"][:500]
        out.append(rec)
    return out


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    services = sorted({r["service_name"] for r in records if r.get("service_name")})
    stamps = sorted(t for t in (r.get("timestamp") for r in records) if t)
    codes = Counter(r["error_code"] for r in records if r.get("error_code"))
    warnings = sum(1 for r in records if r.get("severity") == "WARNING")
    return {
        "services": services,
        "time_start": stamps[0] if stamps else "",
        "time_end": stamps[-1] if stamps else "",
        "record_count": len(records),
        "error_codes": [c for c, _ in codes.most_common(10)],
        "error_count": sum(1 for r in records if r.get("severity") in ("ERROR", "CRITICAL")),
        "warning_count": warnings,
    }


def to_evidence_inputs(records: List[Dict[str, Any]], service: str = "") -> Dict[str, Any]:
    """Shape normalized records into normalizer.normalize_evidence inputs."""
    err_rate = 0.0
    lats, cpus, mems = [], [], []
    for r in records:
        try:
            sc = int(r.get("status_code") or 200)
        except (TypeError, ValueError):
            sc = 200
        if 500 <= sc <= 599:
            err_rate += 1
        try:
            lats.append(float(r.get("latency_ms") or 0))
        except (TypeError, ValueError):
            pass
    total = max(len(records), 1)
    raw_logs = [{
        "timestamp": r.get("timestamp") or "",
        "severity": r.get("severity") or "INFO",
        "payload": {"error_code": r.get("error_code"), "message": r.get("message"),
                    "endpoint": r.get("endpoint")},
        "http_request": {"status": r.get("status_code") or 200,
                         "request_url": r.get("endpoint") or "/"},
        "trace_id": r.get("trace_id"),
    } for r in records[:2000]]
    lats_sorted = sorted(lats)
    p95 = lats_sorted[min(len(lats_sorted) - 1, int(0.95 * len(lats_sorted)))] if lats_sorted else 150.0
    return {
        "raw_logs": raw_logs,
        "raw_metrics": {
            "baseline": {"error_rate_pct": 0.4, "latency_p95_ms": 160.0, "request_count": 550.0,
                         "cpu_utilization_pct": 21.0, "memory_utilization_pct": 36.0},
            "incident": {"error_rate_pct": round(100 * err_rate / total, 1),
                         "latency_p95_ms": round(p95, 1), "request_count": float(len(records)),
                         "cpu_utilization_pct": 21.0, "memory_utilization_pct": 36.0},
        },
    }
