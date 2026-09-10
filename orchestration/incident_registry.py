"""
Incident lifecycle registry (file-backed) + immutable-style activity log.

Statuses: NEW -> COLLECTING_EVIDENCE -> ANALYZING -> ROOT_CAUSE_IDENTIFIED
-> REMEDIATION_PROPOSED -> WAITING_APPROVAL -> APPROVED -> PR_CREATING
-> PR_CREATED -> RESOLVED, with FAILED reachable from active states.
Invalid transitions raise ValueError (tested).
"""
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
INCIDENTS_FILE = os.path.join(BASE, "incidents.json")
ACTIVITY_FILE = os.path.join(BASE, "activity.jsonl")

STATUSES = (
    "NEW", "COLLECTING_EVIDENCE", "ANALYZING", "ROOT_CAUSE_IDENTIFIED",
    "REMEDIATION_PROPOSED", "WAITING_APPROVAL", "APPROVED", "PR_CREATING",
    "PR_CREATED", "RESOLVED", "FAILED",
)

TRANSITIONS: Dict[str, tuple] = {
    "NEW": ("COLLECTING_EVIDENCE", "FAILED"),
    "COLLECTING_EVIDENCE": ("ANALYZING", "FAILED"),
    "ANALYZING": ("ROOT_CAUSE_IDENTIFIED", "FAILED"),
    "ROOT_CAUSE_IDENTIFIED": ("REMEDIATION_PROPOSED", "ANALYZING", "FAILED"),
    "REMEDIATION_PROPOSED": ("WAITING_APPROVAL", "FAILED"),
    "WAITING_APPROVAL": ("APPROVED", "REMEDIATION_PROPOSED", "FAILED"),
    "APPROVED": ("PR_CREATING", "FAILED"),
    "PR_CREATING": ("PR_CREATED", "FAILED"),
    "PR_CREATED": ("RESOLVED", "FAILED"),
    "RESOLVED": (),
    "FAILED": ("COLLECTING_EVIDENCE",),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_activity(event: str, incident_id: str = "", actor: str = "system",
                    description: str = "", metadata: Optional[Dict[str, Any]] = None) -> dict:
    entry = {"timestamp": _now(), "actor": actor, "event": event,
             "incident_id": incident_id, "description": description,
             "metadata": metadata or {}}
    os.makedirs(BASE, exist_ok=True)
    with open(ACTIVITY_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def recent_activity(limit: int = 50, incident_id: str = "") -> List[dict]:
    if not os.path.exists(ACTIVITY_FILE):
        return []
    rows = []
    with open(ACTIVITY_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    if incident_id:
        rows = [r for r in rows if r.get("incident_id") == incident_id]
    return rows[-limit:][::-1]


class IncidentRegistry:
    def __init__(self, path: str = INCIDENTS_FILE):
        self.path = path

    def _load(self) -> Dict[str, dict]:
        try:
            with open(self.path, encoding="utf-8") as f:
                payload = json.load(f)
            return payload if isinstance(payload, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, data: Dict[str, dict]) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self.path)

    def ensure(self, incident_id: str, **fields) -> dict:
        data = self._load()
        if incident_id not in data:
            data[incident_id] = {
                "incident_id": incident_id,
                "project_id": fields.get("project_id", "unassigned"),
                "title": fields.get("title", incident_id),
                "severity": fields.get("severity", "P2"),
                "environment": fields.get("environment", "prod"),
                "services": fields.get("services", []),
                "status": "NEW",
                "evidence_source": fields.get("evidence_source", ""),
                "error_domain": "", "error_subcategory": "",
                "started_at": fields.get("started_at", _now()),
                "rca_runs": [], "notes": [], "pr_id": "",
                "history": [{"at": _now(), "from": "", "to": "NEW"}],
            }
            self._save(data)
        return data[incident_id]

    def get(self, incident_id: str) -> Optional[dict]:
        return self._load().get(incident_id)

    def list(self, project_id: str = "") -> List[dict]:
        rows = list(self._load().values())
        if project_id:
            rows = [r for r in rows if r.get("project_id") == project_id]
        rows.sort(key=lambda r: r.get("started_at", ""), reverse=True)
        return rows

    def transition(self, incident_id: str, target: str, actor: str = "system") -> dict:
        if target not in STATUSES:
            raise ValueError(f"Unknown status {target}")
        data = self._load()
        rec = data.get(incident_id) or self.ensure(incident_id)
        current = rec.get("status", "NEW")
        if target != current and target not in TRANSITIONS.get(current, ()):
            raise ValueError(f"Invalid transition {current} -> {target}")
        if target != current:
            rec["history"].append({"at": _now(), "from": current, "to": target})
            rec["status"] = target
            data[incident_id] = rec
            self._save(data)
            record_activity(f"STATUS_{target}", incident_id, actor,
                            f"{incident_id} moved {current} -> {target}")
        return rec

    def add_rca_run(self, incident_id: str, run: dict) -> dict:
        data = self._load()
        rec = data.get(incident_id) or self.ensure(incident_id)
        runs = rec.get("rca_runs", [])
        run = dict(run)
        run["run_number"] = len(runs) + 1
        run.setdefault("at", _now())
        runs.append(run)
        rec["rca_runs"] = runs
        data[incident_id] = rec
        self._save(data)
        return rec

    def add_note(self, incident_id: str, author: str, text: str) -> dict:
        data = self._load()
        rec = data.get(incident_id) or self.ensure(incident_id)
        rec.setdefault("notes", []).append(
            {"at": _now(), "author": author, "text": text[:2000]})
        data[incident_id] = rec
        self._save(data)
        return rec

    def set_fields(self, incident_id: str, **fields) -> dict:
        data = self._load()
        rec = data.get(incident_id) or self.ensure(incident_id)
        rec.update(fields)
        data[incident_id] = rec
        self._save(data)
        return rec
