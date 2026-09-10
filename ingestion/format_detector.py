"""Format + source auto-detection for uploaded logs.

Returns (format, confidence, note). Low confidence yields
"partially recognized" and parsing continues with reliable fields only.
"""
import csv
import io
import json
from typing import Tuple

FORMATS = ("json", "jsonl", "csv", "text")


def detect_format(filename: str, content: bytes) -> Tuple[str, float, str]:
    text = content.decode("utf-8", errors="ignore").strip()
    if not text:
        return "text", 0.0, "empty file"
    if filename.endswith(".json"):
        try:
            payload = json.loads(text)
            if isinstance(payload, (dict, list)):
                return "json", 0.95, "valid JSON document"
        except ValueError:
            pass
    lines = [l for l in text.splitlines() if l.strip()][:20]
    if filename.endswith(".jsonl") or (
        len(lines) >= 2 and sum(1 for l in lines if _is_json(l)) / max(len(lines), 1) > 0.8
    ):
        return "jsonl", 0.9, "one JSON object per line"
    if filename.endswith(".csv") or ("," in (lines[0] if lines else "") and len(lines) > 1):
        try:
            dialect = csv.Sniffer().sniff("\n".join(lines[:5]), delimiters=",;\t")
            reader = csv.reader(io.StringIO("\n".join(lines[:5])), dialect)
            header = next(reader, [])
            if len(header) >= 2:
                return "csv", 0.85, f"delimiter {dialect.delimiter!r}, {len(header)} columns"
        except Exception:
            pass
    if _is_json(text):
        return "json", 0.9, "single JSON object"
    return "text", 0.7, "plain text lines"


def _is_json(line: str) -> bool:
    line = line.strip()
    if not (line.startswith("{") and line.endswith("}")):
        return False
    try:
        json.loads(line)
        return True
    except ValueError:
        return False


SOURCE_HINTS = [
    ("kubernetes", ("kube", "pod/", "container:")),
    ("database", ("postgres", "mysql", "sql", "query ", "slow query")),
    ("load balancer", ("backend_latency", "target_group", "alb", "elb")),
    ("api gateway", ("apigateway", "route:", "apiproxy")),
    ("cloud run", ("run.googleapis.com", "cloud_run", "revision_name")),
    ("system", ("kernel:", "systemd", "oom", "cpu throttling")),
]


def detect_source(filename: str, sample_lines: list) -> Tuple[str, float]:
    blob = (filename + "\n" + "\n".join(sample_lines[:30])).lower()
    for source, hints in SOURCE_HINTS:
        if any(h in blob for h in hints):
            return (source.title() + " Logs", 0.8)
    if any(w in blob for w in ("traceback", "exception", "error_code", "status_code")):
        return ("Application Logs", 0.75)
    return ("Mixed Logs", 0.5)
