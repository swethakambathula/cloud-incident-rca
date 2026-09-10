"""Evidence completeness: logs/metrics/deployments/traces/repo/knowledge."""
from typing import Dict, List


def completeness(incident: Dict = None, attachments: List[Dict] = None,
                 project: Dict = None, rca_runs: int = 0) -> Dict:
    incident = incident or {}
    attachments = attachments or []
    project = project or {}
    has_logs = bool(attachments) or bool(incident.get("evidence_source"))
    has_metrics = bool((incident.get("rca_runs") or rca_runs)) or has_logs
    deployments = bool(incident.get("scenario_id") or incident.get("evidence_source") or has_logs)
    traces = any("trace" in str(a.get("filename", "")).lower() for a in attachments)
    repo = bool((project.get("repository_url") or project.get("local_path")))
    knowledge = True  # runbooks always available locally
    parts = [("Logs", has_logs), ("Metrics", has_metrics), ("Deployments", deployments),
             ("Traces", traces), ("Repository", repo), ("Knowledge", knowledge)]
    pct = round(100 * sum(1 for _, ok in parts if ok) / len(parts))
    return {"percent": pct,
            "items": [{"name": n, "status": "Ready" if ok else "Missing"} for n, ok in parts]}
