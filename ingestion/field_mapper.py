"""Alias maps: vendor column/key names -> NormalizedLogRecord fields.

Unknown keys land in metadata. Missing fields stay None (never hallucinated).
"""
from typing import Any, Dict

FIELD_ALIASES: Dict[str, tuple] = {
    "timestamp": ("timestamp", "time", "@timestamp", "datetime", "date"),
    "severity": ("severity", "level", "log_level", "loglevel"),
    "service_name": ("service_name", "service", "serviceName", "app", "component"),
    "component": ("component", "logger", "module"),
    "host": ("host", "hostname", "instance", "pod"),
    "revision": ("revision", "revision_name", "version"),
    "environment": ("environment", "env"),
    "request_id": ("request_id", "requestId", "req_id", "rid"),
    "trace_id": ("trace_id", "traceId", "trace", "trace_id_full"),
    "span_id": ("span_id", "spanId", "span"),
    "endpoint": ("endpoint", "path", "url", "request_url", "route"),
    "method": ("method", "http_method", "verb"),
    "status_code": ("status_code", "status", "statusCode", "code"),
    "latency_ms": ("latency_ms", "latency", "latencyMs", "duration_ms", "durationMs", "elapsed_ms"),
    "error_code": ("error_code", "errorCode", "error", "exception", "err"),
    "message": ("message", "msg", "text", "log", "detail"),
    "dependency": ("dependency", "downstream", "target_service"),
    "region": ("region", "zone", "location"),
    "incident_id": ("incident_id", "incidentId"),
}

SEVERITY_MAP = {
    "debug": "DEBUG", "info": "INFO", "information": "INFO",
    "warn": "WARNING", "warning": "WARNING", "error": "ERROR",
    "err": "ERROR", "fatal": "CRITICAL", "critical": "CRITICAL", "crit": "CRITICAL",
}


def _norm_key(key: str) -> str:
    return "".join(ch for ch in str(key).lower() if ch.isalnum())


_ALIAS_INDEX: Dict[str, str] = {}
for _field, _aliases in FIELD_ALIASES.items():
    for _a in _aliases:
        _ALIAS_INDEX.setdefault(_norm_key(_a), _field)


def map_record(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Map one raw dict onto normalized fields; leftovers go to metadata."""
    out: Dict[str, Any] = {f: None for f in FIELD_ALIASES}
    out["metadata"] = {}
    for key, value in (raw or {}).items():
        field = _ALIAS_INDEX.get(_norm_key(key))
        if field and out[field] is None:
            out[field] = value
        elif field:
            out["metadata"][key] = value
        else:
            out["metadata"][key] = value
    sev = out.get("severity")
    if isinstance(sev, str):
        out["severity"] = SEVERITY_MAP.get(sev.strip().lower(), sev.strip().upper())
    for numeric in ("status_code", "latency_ms"):
        val = out.get(numeric)
        if isinstance(val, str):
            try:
                out[numeric] = float(val) if "." in val else int(val)
            except ValueError:
                out[numeric] = None
    return out
