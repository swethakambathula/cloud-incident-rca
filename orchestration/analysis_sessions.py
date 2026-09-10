"""AnalysisSession: analyze-only log sessions that create NO incident.

A session may later be converted (attach to existing incident or create a
new LOG_UPLOAD incident) without duplicating RCA logic.
"""
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
SESSIONS_FILE = os.path.join(BASE, "analysis_sessions.json")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load(path: str = SESSIONS_FILE) -> Dict[str, dict]:
    try:
        with open(path, encoding="utf-8") as f:
            payload = json.load(f)
        return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(data: Dict[str, dict], path: str = SESSIONS_FILE) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


class AnalysisSessionStore:
    def __init__(self, path: str = SESSIONS_FILE):
        self.path = path

    def create(self, project_id: str, analysis_ids: List[str],
               context: Optional[Dict] = None) -> dict:
        data = _load(self.path)
        session_id = f"AS-{uuid.uuid4().hex[:8].upper()}"
        rec = {"session_id": session_id, "project_id": project_id,
               "analysis_ids": analysis_ids, "context": context or {},
               "converted_incident_id": "", "created_at": _now()}
        data[session_id] = rec
        _save(data, self.path)
        return rec

    def get(self, session_id: str) -> Optional[dict]:
        return _load(self.path).get(session_id)

    def mark_converted(self, session_id: str, incident_id: str) -> Optional[dict]:
        data = _load(self.path)
        rec = data.get(session_id)
        if not rec:
            return None
        rec["converted_incident_id"] = incident_id
        _save(data, self.path)
        return rec
