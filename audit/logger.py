"""
Audit logger - append-only records for sensitive actions.
"""
import json, logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

AUDIT_PATH = Path(__file__).parent.parent / "data" / "audit.log"
logger = logging.getLogger("audit")

def audit_log(event_type: str, incident_id: str, actor: str, action: str, target: str, before: Any=None, after: Any=None, approval_id: str=None, result: Any=None):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "incident_id": incident_id,
        "actor": actor,
        "action": action,
        "target": target,
        "approval_id": approval_id,
        "before": before,
        "after": after,
        "result": str(result)[:1000] if result else None,
    }
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info(f"AUDIT {event_type} {incident_id} {action} by {actor}")
    return entry
