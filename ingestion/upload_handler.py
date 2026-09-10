"""Upload intake: extension/size guardrails, durable storage, per-file parse stats."""
import os
import uuid
from typing import Dict, List, Tuple

from ingestion.format_detector import detect_format, detect_source
from ingestion.log_parser import parse_file

ALLOWED_EXTENSIONS = (".log", ".txt", ".json", ".jsonl", ".csv")
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILES = 4

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "uploads")


def validate_filename(filename: str) -> Tuple[bool, str]:
    if not filename:
        return False, "missing filename"
    if not filename.lower().endswith(ALLOWED_EXTENSIONS):
        return False, f"extension not supported (allowed: {', '.join(ALLOWED_EXTENSIONS)})"
    if "/" in filename or "\\" in filename:
        return False, "nested paths not allowed"
    return True, ""


def store_upload(analysis_id: str, filename: str, content: bytes) -> str:
    folder = os.path.join(BASE, analysis_id)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, filename)
    with open(path, "wb") as f:
        f.write(content)
    return path


def ingest_files(files: List[Tuple[str, bytes]], source_type: str = "Auto Detect") -> Tuple[str, List[dict], List[dict], List[str]]:
    """Parse uploads -> (analysis_id, file_summaries, preview_records, warnings).

    Full parsed records persist under data/uploads/{analysis_id}/parsed.json
    for the analyze step; only a normalized preview is returned inline.
    """
    import json as _json

    from ingestion.normalizer import normalize

    all_raw: List[dict] = []
    summaries: List[dict] = []
    warnings: List[str] = []
    analysis_id = f"AN-{uuid.uuid4().hex[:8].upper()}"
    for filename, content in files[:MAX_FILES]:
        ok, reason = validate_filename(filename)
        if not ok:
            summaries.append({"filename": filename, "size_bytes": len(content),
                              "parse_status": "rejected", "parse_note": reason})
            warnings.append(f"{filename}: {reason}")
            continue
        if len(content) > MAX_FILE_BYTES:
            summaries.append({"filename": filename, "size_bytes": len(content),
                              "parse_status": "rejected", "parse_note": "file exceeds 25 MB"})
            warnings.append(f"{filename}: file exceeds 25 MB")
            continue
        store_upload(analysis_id, filename, content)
        records, stats = parse_file(filename, content,
                                    "" if source_type == "Auto Detect" else "")
        sample = [str(r.get("raw_line") or r.get("message") or "") for r in records[:30]]
        src_name, _ = detect_source(filename, sample)
        summaries.append({
            "filename": filename, "size_bytes": len(content),
            "detected_format": stats.get("format", ""),
            "detected_source": src_name if source_type == "Auto Detect" else source_type,
            "record_count": stats.get("parsed", 0),
            "time_start": "", "time_end": "",
            "parse_status": "parsed" if not stats.get("partial") else "partial",
            "parse_note": stats.get("partial_note") or stats.get("note", ""),
        })
        if stats.get("partial"):
            warnings.append(f"{filename}: {stats.get('partial_note')}")
        all_raw.extend(records)
    folder = os.path.join(BASE, analysis_id)
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "parsed.json"), "w", encoding="utf-8") as f:
        _json.dump(all_raw, f)
    normalized_preview = normalize(all_raw[:200])
    return analysis_id, summaries, normalized_preview, warnings


def load_parsed(analysis_id: str) -> List[dict]:
    """Reload persisted parsed records for analysis. Guards path traversal."""
    import json as _json

    if not analysis_id.replace("-", "").replace("_", "").isalnum():
        return []
    path = os.path.join(BASE, analysis_id, "parsed.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            payload = _json.load(f)
        return payload if isinstance(payload, list) else []
    except (OSError, ValueError):
        return []
