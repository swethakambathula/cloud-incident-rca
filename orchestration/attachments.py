"""Persistent per-incident evidence attachments with SHA256 dedup.

Every uploaded log is linked to a specific incident + project, never stored
as global anonymous data. Duplicate content (same SHA256) for the same
incident is rejected with a warning instead of being parsed twice.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
ATTACHMENTS_FILE = os.path.join(BASE, "incident_attachments.json")
ATTACHMENT_BLOBS = os.path.join(BASE, "attachments")

ATTACHMENT_TYPES = (
    "APPLICATION_LOG", "ACCESS_LOG", "METRIC_EXPORT", "TRACE_EXPORT",
    "DEPLOYMENT_LOG", "CONFIG_SNAPSHOT", "OTHER",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _load() -> List[dict]:
    try:
        with open(ATTACHMENTS_FILE, encoding="utf-8") as f:
            payload = json.load(f)
        return payload if isinstance(payload, list) else []
    except (OSError, ValueError):
        return []


def _save(rows: List[dict]) -> None:
    os.makedirs(BASE, exist_ok=True)
    tmp = ATTACHMENTS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    os.replace(tmp, ATTACHMENTS_FILE)


def _guess_type(filename: str) -> str:
    low = (filename or "").lower()
    if low.endswith((".log", ".txt", ".json", ".jsonl")):
        return "APPLICATION_LOG"
    if low.endswith(".csv"):
        return "METRIC_EXPORT"
    return "OTHER"


class AttachmentStore:
    def __init__(self, path: str = ATTACHMENTS_FILE):
        self.path = path

    def _load(self) -> List[dict]:
        if self.path == ATTACHMENTS_FILE:
            return _load()
        try:
            with open(self.path, encoding="utf-8") as f:
                payload = json.load(f)
            return payload if isinstance(payload, list) else []
        except (OSError, ValueError):
            return []

    def _save(self, rows: List[dict]) -> None:
        if self.path == ATTACHMENTS_FILE:
            _save(rows)
            return
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        os.replace(tmp, self.path)

    def list(self, incident_id: str = "") -> List[dict]:
        rows = self._load()
        if incident_id:
            rows = [r for r in rows if r.get("incident_id") == incident_id]
        rows.sort(key=lambda r: r.get("uploaded_at", ""))
        return rows

    def find_duplicate(self, incident_id: str, sha256: str) -> Optional[dict]:
        for r in self._load():
            if r.get("incident_id") == incident_id and r.get("sha256") == sha256:
                return r
        return None

    def attach(self, incident_id: str, project_id: str, filename: str,
               content: bytes, content_type: str = "",
               attachment_type: str = "", uploaded_by: str = "web-user",
               source: str = "upload") -> dict:
        """Persist blob + parse once. Raises ValueError on duplicate."""
        digest = _sha256(content)
        dup = self.find_duplicate(incident_id, digest)
        if dup:
            raise ValueError(
                f"This file is already attached to this incident ({dup.get('filename')}).")
        # parse once for event count
        parsed_event_count = 0
        parse_status = "parsed"
        try:
            from ingestion.log_parser import parse_file
            records, stats = parse_file(filename, content)
            parsed_event_count = int(stats.get("parsed", len(records)))
        except Exception as e:
            parse_status = f"parse_error: {e}"[:200]
        att_id = f"ATT-{digest[:8].upper()}"
        folder = os.path.join(ATTACHMENT_BLOBS, incident_id)
        os.makedirs(folder, exist_ok=True)
        safe_name = (filename or "upload.log").replace("/", "_").replace("\\", "_")
        blob_path = os.path.join(folder, f"{att_id}__{safe_name}")
        with open(blob_path, "wb") as f:
            f.write(content)
        record = {
            "id": att_id,
            "incident_id": incident_id,
            "project_id": project_id,
            "source_type": source,
            "type": attachment_type or _guess_type(filename),
            "filename": safe_name,
            "original_filename": filename,
            "content_type": content_type or "application/octet-stream",
            "mime_type": content_type or "application/octet-stream",
            "size": len(content),
            "storage_location": blob_path,
            "sha256": digest,
            "uploaded_by": uploaded_by,
            "uploaded_at": _now(),
            "status": "ready",
            "parse_status": parse_status,
            "parsed_event_count": parsed_event_count,
        }
        rows = self._load()
        rows.append(record)
        self._save(rows)
        return record

    def remove(self, attachment_id: str, incident_id: str = "") -> bool:
        rows = self._load()
        kept = [r for r in rows
                if not (r.get("id") == attachment_id
                        and (not incident_id or r.get("incident_id") == incident_id))]
        if len(kept) == len(rows):
            return False
        self._save(kept)
        return True

    def raw_text(self, attachment_id: str, incident_id: str = "", limit_bytes: int = 200000) -> str:
        for r in self._load():
            if r.get("id") == attachment_id and (not incident_id or r.get("incident_id") == incident_id):
                try:
                    with open(r["storage_location"], "rb") as f:
                        return f.read(limit_bytes).decode("utf-8", errors="ignore")
                except OSError:
                    return ""
        return ""
