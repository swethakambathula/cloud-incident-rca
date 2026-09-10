"""Guided demo steps derived from live incident state.

Guides the operator through stages without auto-completing anything:
human approval is always an explicit step and is never bypassed.
"""
from typing import Dict, List


def guide_steps(rec: Dict = None, has_rca: bool = False,
                has_fix: bool = False, has_pr: bool = False,
                verified: bool = False) -> List[Dict]:
    rec = rec or {}
    status = rec.get("status", "NEW")
    steps = [
        {"step": 1, "title": "Incident created",
         "done": True, "action": "Continue", "target": "evidence"},
        {"step": 2, "title": "Evidence generated",
         "done": bool(rec.get("evidence_source") or rec.get("scenario_id")),
         "action": "Inspect Logs", "target": "evidence"},
        {"step": 3, "title": "Run RCA",
         "done": has_rca, "action": "Run RCA", "target": "investigation"},
        {"step": 4, "title": "Root cause found",
         "done": has_rca and status not in ("NEW", "COLLECTING_EVIDENCE", "ANALYZING"),
         "action": "Inspect Investigation", "target": "investigation"},
        {"step": 5, "title": "Generate fix",
         "done": has_fix, "action": "Generate Fix", "target": "remediation"},
        {"step": 6, "title": "Review approval (human decision required)",
         "done": status in ("APPROVED", "PR_CREATING", "PR_CREATED", "RESOLVED"),
         "action": "Review Fix", "target": "approvals",
         "note": "Approval is never automatic."},
        {"step": 7, "title": "Create PR",
         "done": has_pr, "action": "Approve & Create PR", "target": "approvals"},
        {"step": 8, "title": "Verify",
         "done": verified, "action": "Run Verification", "target": "remediation"},
    ]
    current = next((s["step"] for s in steps if not s["done"]), 8)
    for s in steps:
        s["current"] = (s["step"] == current)
    return steps
