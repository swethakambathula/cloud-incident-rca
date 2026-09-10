"""Parsers: text / json / jsonl / csv -> list of raw dicts plus parse stats."""
import csv
import io
import json
import re
from typing import Any, Dict, List, Tuple

TEXT_RE = re.compile(
    r"^(?P<timestamp>\S+)?\s*(?P<severity>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)?\s*"
    r"(?P<service>[\w\-/.]+)?\s*(?P<rest>.*)$"
)
STATUS_RE = re.compile(r"\b(?:status(?:_code)?|HTTP)[ =:]+(\d{3})\b", re.IGNORECASE)
LAT_RE = re.compile(r"\b(?:latency|duration|elapsed)[ =:]+(\d+(?:\.\d+)?)\s*(ms|s)?\b", re.IGNORECASE)
TRACE_RE = re.compile(r"\b(?:trace[_-]?id|trace)[ =:]+([A-Za-z0-9_\-/]{8,64})", re.IGNORECASE)
ERRCODE_RE = re.compile(r"\b([A-Z][A-Z0-9_]{3,40})\b")
MAX_RECORDS = 50000


def parse_text(text: str) -> Tuple[List[Dict[str, Any]], dict]:
    records, skipped = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = TEXT_RE.match(line)
        rec: Dict[str, Any] = {"raw_line": line}
        if m:
            gd = m.groupdict()
            rec["timestamp"] = gd.get("timestamp") or ""
            rec["severity"] = (gd.get("severity") or "").upper().replace("WARN", "WARNING")
            rest = gd.get("rest") or ""
            svc = gd.get("service") or ""
            if svc and not re.search(r"\s", svc) and len(svc) < 64:
                rec["service_name"] = svc
            sm = STATUS_RE.search(line)
            if sm:
                rec["status_code"] = int(sm.group(1))
            lm = LAT_RE.search(line)
            if lm:
                val = float(lm.group(1))
                rec["latency_ms"] = val * 1000 if (lm.group(2) or "").lower() == "s" else val
            tm = TRACE_RE.search(line)
            if tm:
                rec["trace_id"] = tm.group(1)
            codes = [c for c in ERRCODE_RE.findall(line)
                     if c not in ("HTTP", "UTC", "ERROR", "WARNING", "INFO", "DEBUG", "CRITICAL")]
            if codes:
                rec["error_code"] = codes[0]
            rec["message"] = rest[:500] or line[:500]
        else:
            skipped += 1
            rec["message"] = line[:500]
        records.append(rec)
        if len(records) >= MAX_RECORDS:
            break
    return records, {"parsed": len(records), "skipped": skipped}


def parse_json_doc(text: str) -> Tuple[List[Dict[str, Any]], dict]:
    try:
        payload = json.loads(text)
    except ValueError as e:
        return [], {"parsed": 0, "skipped": 0, "error": f"invalid JSON: {e}"}
    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return [], {"parsed": 0, "skipped": 0, "error": "top-level JSON must be object or array"}
    records = [r for r in payload[:MAX_RECORDS] if isinstance(r, dict)]
    return records, {"parsed": len(records), "skipped": max(len(payload) - len(records), 0)}


def parse_jsonl(text: str) -> Tuple[List[Dict[str, Any]], dict]:
    records, skipped = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
            else:
                skipped += 1
        except ValueError:
            skipped += 1
        if len(records) >= MAX_RECORDS:
            break
    return records, {"parsed": len(records), "skipped": skipped}


def parse_csv(text: str) -> Tuple[List[Dict[str, Any]], dict]:
    try:
        sample = "\n".join(text.splitlines()[:5])
        import csv as _csv

        dialect = _csv.Sniffer().sniff(sample, delimiters=",;\t")
    except Exception:
        dialect = None
    reader = csv.DictReader(io.StringIO(text), dialect=dialect) if dialect else csv.DictReader(io.StringIO(text))
    records = [dict(r) for _, r in zip(range(MAX_RECORDS), reader) if any(r.values())]
    return records, {"parsed": len(records), "skipped": 0,
                     "columns": reader.fieldnames or []}


def parse_file(filename: str, content: bytes, declared_format: str = "") -> Tuple[List[Dict[str, Any]], dict]:
    from ingestion.format_detector import detect_format

    text = content.decode("utf-8", errors="ignore")
    fmt, conf, note = detect_format(filename, content)
    if declared_format and declared_format in ("json", "jsonl", "csv", "text"):
        fmt = declared_format
    if fmt == "json":
        records, stats = parse_json_doc(text)
    elif fmt == "jsonl":
        records, stats = parse_jsonl(text)
    elif fmt == "csv":
        records, stats = parse_csv(text)
    else:
        records, stats = parse_text(text)
    stats.update({"format": fmt, "confidence": conf, "note": note,
                  "partial": conf < 0.6,
                  "partial_note": "Log format partially recognized." if conf < 0.6 else ""})
    return records, stats
