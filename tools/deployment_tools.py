"""
Cloud Run Revision and Deployment Tools.
Queries Google Cloud Run API (run_v2) for active revisions, traffic allocations,
creation timestamps, and configuration diffs.
"""
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger("deployment_tools")

try:
    from google.cloud import run_v2
    HAS_GCP_RUN = True
except ImportError:
    HAS_GCP_RUN = False


def _get_services_client() -> Optional[Any]:
    if not HAS_GCP_RUN:
        return None
    try:
        return run_v2.ServicesClient()
    except Exception as e:
        logger.warning(f"Could not initialize Cloud Run ServicesClient: {e}")
        return None


def _get_revisions_client() -> Optional[Any]:
    if not HAS_GCP_RUN:
        return None
    try:
        return run_v2.RevisionsClient()
    except Exception as e:
        logger.warning(f"Could not initialize Cloud Run RevisionsClient: {e}")
        return None


def get_current_revision(
    project_id: str,
    region: str,
    service_name: str
) -> Optional[Dict[str, Any]]:
    """Fetches the primary 100% traffic or latest active revision for a Cloud Run service."""
    client = _get_services_client()
    if not client:
        return {
            "revision_name": f"{service_name}-00004-v1",
            "status": "MOCK_ACTIVE",
            "traffic_percent": 100
        }

    try:
        name = f"projects/{project_id}/locations/{region}/services/{service_name}"
        service = client.get_service(name=name, timeout=5.0)

        traffic_allocations = []
        for t in service.traffic:
            traffic_allocations.append({
                "revision": t.revision,
                "percent": t.percent,
                "type": str(t.type_)
            })

        latest_rev = service.latest_ready_revision.split("/")[-1] if service.latest_ready_revision else None
        return {
            "service_name": service_name,
            "latest_ready_revision": latest_rev,
            "traffic": traffic_allocations
        }
    except Exception as e:
        logger.warning(f"get_current_revision failed: {e}")
        return {
            "revision_name": f"{service_name}-active",
            "error": str(e)
        }


def get_recent_revisions(
    project_id: str,
    region: str,
    service_name: str,
    limit: int = 5
) -> List[Dict[str, Any]]:
    """Lists the most recent Cloud Run revisions deployed for a service."""
    client = _get_revisions_client()
    if not client:
        return [
            {
                "revision_name": f"{service_name}-00004-v1",
                "creation_time": datetime.now(timezone.utc).isoformat(),
                "traffic_percent": 100
            }
        ]

    try:
        parent = f"projects/{project_id}/locations/{region}/services/{service_name}"
        revisions = client.list_revisions(parent=parent, timeout=5.0)

        results = []
        for rev in revisions:
            name = rev.name.split("/")[-1]
            create_time = rev.create_time.isoformat() if getattr(rev, "create_time", None) else None
            containers = []
            for c in rev.containers:
                containers.append({
                    "image": c.image,
                    "env": {e.name: e.value for e in c.env}
                })

            results.append({
                "revision_name": name,
                "creation_time": create_time,
                "containers": containers
            })
            if len(results) >= limit:
                break

        return results
    except Exception as e:
        logger.warning(f"get_recent_revisions failed: {e}")
        return []


def get_revision_creation_time(
    project_id: str,
    region: str,
    service_name: str,
    revision_name: str
) -> Optional[str]:
    """Retrieves creation ISO timestamp of a specific revision."""
    revs = get_recent_revisions(project_id, region, service_name, limit=10)
    for r in revs:
        if r.get("revision_name") == revision_name:
            return r.get("creation_time")
    return None


def get_revision_traffic_split(
    project_id: str,
    region: str,
    service_name: str
) -> Dict[str, int]:
    """Returns mapping of revision_name -> traffic percentage."""
    info = get_current_revision(project_id, region, service_name)
    traffic_map = {}
    for t in info.get("traffic", []):
        rev = t.get("revision")
        if rev:
            traffic_map[rev] = t.get("percent", 0)
    return traffic_map


def get_revision_configuration(
    project_id: str,
    region: str,
    service_name: str,
    revision_name: str
) -> Dict[str, Any]:
    """Retrieves container image and environment configuration for a revision."""
    revs = get_recent_revisions(project_id, region, service_name, limit=10)
    for r in revs:
        if r.get("revision_name") == revision_name:
            return {
                "revision_name": revision_name,
                "containers": r.get("containers", [])
            }
    return {"revision_name": revision_name, "containers": []}


def compare_revisions(
    rev_a: Dict[str, Any],
    rev_b: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Compares two revision configurations.
    Identifies changed container images and environment variable diffs.
    """
    containers_a = rev_a.get("containers", [{}])
    containers_b = rev_b.get("containers", [{}])

    image_a = containers_a[0].get("image") if containers_a else None
    image_b = containers_b[0].get("image") if containers_b else None

    env_a = containers_a[0].get("env", {}) if containers_a else {}
    env_b = containers_b[0].get("env", {}) if containers_b else {}

    added_env = [k for k in env_b if k not in env_a]
    removed_env = [k for k in env_a if k not in env_b]
    modified_env = [k for k in env_a if k in env_b and env_a[k] != env_b[k]]

    return {
        "image_changed": image_a != image_b,
        "image_a": image_a,
        "image_b": image_b,
        "added_env_vars": added_env,
        "removed_env_vars": removed_env,
        "modified_env_vars": modified_env,
        "has_config_changes": bool(image_a != image_b or added_env or removed_env or modified_env)
    }
