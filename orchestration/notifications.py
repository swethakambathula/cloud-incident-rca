"""
Notification hooks (interfaces, no hardcoded providers).

Every notify() call fans out to:
- registered subscribers (e.g. a future Slack sink via subscribe())
- the audit log and activity timeline (always, no network)

Events: RCA_COMPLETE, APPROVAL_REQUESTED, APPROVAL_DECIDED, PR_CREATED, PR_FAILED.
"""
import logging
from typing import Callable, Dict, List

logger = logging.getLogger("notifications")

_subscribers: List[Callable[[str, dict], None]] = []


def subscribe(handler: Callable[[str, dict], None]) -> None:
    _subscribers.append(handler)


def notify(event: str, payload: Dict | None = None) -> Dict:
    payload = dict(payload or {})
    for handler in list(_subscribers):
        try:
            handler(event, payload)
        except Exception as e:  # a sink must never break the pipeline
            logger.warning(f"notification sink failed for {event}: {e}")
    try:
        from audit.logger import audit_log
        from orchestration.incident_registry import record_activity
        audit_log(f"NOTIFY_{event}", payload.get("incident_id", ""),
                  "notifier", event, payload.get("target", ""))
        record_activity(event, payload.get("incident_id", ""), "notifier",
                        payload.get("description", event), payload)
    except Exception as e:
        logger.warning(f"notification persistence failed: {e}")
    return {"event": event, "sinks": len(_subscribers)}
