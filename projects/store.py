"""
File-backed stores: projects, agent PR registry, log analyses.

JSON/JSONL under data/ so records survive restarts (unlike the in-memory
approval/FIX_JOBS managers). A default project is seeded so existing
incidents and PRs attach to something immediately.
"""
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from schemas.project import Project, PullRequestRecord, LogAnalysis

BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
PROJECTS_FILE = os.path.join(BASE, "projects.json")
PRS_FILE = os.path.join(BASE, "agent_prs.jsonl")
ANALYSES_FILE = os.path.join(BASE, "log_analyses.jsonl")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_json(path: str, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write_json(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, path)


def _append_jsonl(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")


def _read_jsonl(path: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
    return rows


DEFAULT_PROJECT = {
    "project_id": "checkout-platform",
    "name": "Checkout Platform",
    "description": "Demo checkout/orders/payments platform used by the RCA agent.",
    "environment": "production",
    "team_owner": "sre-demo",
    "repository_url": "https://github.com/swethakambathula/cloud-rca-demo-app.git",
    "provider": "github",
    "default_branch": "main",
    "local_path": "cloud-rca-demo-app",
    "gcp_project_id": os.getenv("GOOGLE_CLOUD_PROJECT", ""),
    "region": os.getenv("GOOGLE_CLOUD_REGION", "us-central1"),
    "services": ["checkout-service", "orders-service", "payments-service"],
    "status": "active",
    "created_at": "2026-09-01T00:00:00+00:00",
    "last_scan": "",
    "detected": {},
    "data_sources": [
        {"kind": "git", "status": "connected", "detail": "cloud-rca-demo-app"},
        {"kind": "gcp", "status": "connected", "detail": "telemetry"},
    ],
    "repo_access": "PR_CREATION_ENABLED",
}


class ProjectStore:
    def __init__(self, path: str = PROJECTS_FILE):
        self.path = path

    def _load(self) -> Dict[str, dict]:
        data = _read_json(self.path, {})
        if "checkout-platform" not in data:
            data["checkout-platform"] = dict(DEFAULT_PROJECT)
            _write_json(self.path, data)
        return data

    def _save(self, data: Dict[str, dict]) -> None:
        _write_json(self.path, data)

    def list(self) -> List[Project]:
        return [Project(**p) for p in self._load().values()]

    def get(self, project_id: str) -> Optional[Project]:
        data = self._load().get(project_id)
        return Project(**data) if data else None

    def upsert(self, project: Project) -> Project:
        data = self._load()
        data[project.project_id] = project.model_dump()
        self._save(data)
        return project

    def delete(self, project_id: str) -> bool:
        data = self._load()
        if project_id in data and project_id != "checkout-platform":
            del data[project_id]
            self._save(data)
            return True
        return False

    def resolve_project(self, service: str = "", repository: str = "") -> str:
        """Map a service or repository to an onboarded project (or unassigned)."""
        for pid, p in self._load().items():
            if service and service in (p.get("services") or []):
                return pid
            if repository and repository and repository in (p.get("repository_url") or ""):
                return pid
        return "unassigned"


class PRRegistry:
    def __init__(self, path: str = PRS_FILE):
        self.path = path

    def record(self, pr: PullRequestRecord) -> PullRequestRecord:
        _append_jsonl(self.path, pr.model_dump())
        return pr

    def list(self, project_id: str = "") -> List[PullRequestRecord]:
        rows = [PullRequestRecord(**r) for r in _read_jsonl(self.path)]
        rows.sort(key=lambda r: r.created_at or "", reverse=True)
        if project_id:
            rows = [r for r in rows if r.project_id == project_id]
        return rows

    def get(self, pr_id: str) -> Optional[PullRequestRecord]:
        for r in _read_jsonl(self.path):
            if r.get("pr_id") == pr_id:
                return PullRequestRecord(**r)
        return None

    def by_incident(self, incident_id: str) -> List[PullRequestRecord]:
        return [r for r in self.list() if r.incident_id == incident_id]


class AnalysisStore:
    def __init__(self, path: str = ANALYSES_FILE):
        self.path = path

    def save(self, analysis: LogAnalysis) -> LogAnalysis:
        rows = [r for r in _read_jsonl(self.path) if r.get("analysis_id") != analysis.analysis_id]
        rows.append(analysis.model_dump())
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        return analysis

    def list(self) -> List[LogAnalysis]:
        rows = [LogAnalysis(**r) for r in _read_jsonl(self.path)]
        rows.sort(key=lambda r: r.created_at or "", reverse=True)
        return rows

    def get(self, analysis_id: str) -> Optional[LogAnalysis]:
        for r in _read_jsonl(self.path):
            if r.get("analysis_id") == analysis_id:
                return LogAnalysis(**r)
        return None
