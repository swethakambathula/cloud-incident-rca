"""Backend-derived product effectiveness metrics. Never fabricated.

Every metric carries its sample size; thin samples report "Not enough data".
"""
from datetime import datetime
from typing import Dict, List


def _parse(ts: str):
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def _minutes(a: str, b: str):
    t1, t2 = _parse(a), _parse(b)
    if t1 is None or t2 is None:
        return None
    return (t2 - t1).total_seconds() / 60


def compute(incidents: List[Dict], prs: List[Dict], memories: List[Dict],
            approvals: List[Dict]) -> Dict:
    out: Dict[str, Dict] = {}

    def metric(value, samples: int, unit: str = "", minimum: int = 2):
        if samples < minimum:
            return {"value": None, "samples": samples, "unit": unit,
                    "note": "Not enough data"}
        return {"value": value, "samples": samples, "unit": unit, "note": ""}

    runs = [(rec, r) for rec in incidents for r in (rec.get("rca_runs") or [])]
    mttr, mttr_n = [], 0
    for rec, r in runs:
        mins = _minutes(rec.get("started_at", ""), r.get("at", ""))
        if mins is not None and mins >= 0:
            mttr.append(mins)
            mttr_n += 1
    out["mean_time_to_root_cause"] = metric(
        round(sum(mttr) / len(mttr), 1) if mttr else None, mttr_n, "minutes")

    appr_by_inc: Dict[str, List[Dict]] = {}
    for a in approvals:
        appr_by_inc.setdefault(a.get("incident_id", ""), []).append(a)
    mttp = []
    for rec in incidents:
        first = sorted([a.get("requested_at", "") for a in appr_by_inc.get(rec.get("incident_id", ""), []) if a.get("requested_at")])
        if first:
            mins = _minutes(rec.get("started_at", ""), first[0])
            if mins is not None and mins >= 0:
                mttp.append(mins)
    out["mean_time_to_remediation_proposal"] = metric(
        round(sum(mttp) / len(mttp), 1) if mttp else None, len(mttp), "minutes")

    with_runs = [rec for rec in incidents if rec.get("rca_runs")]
    resolved = [rec for rec in with_runs if rec.get("status") == "RESOLVED"]
    out["rca_success_rate"] = metric(
        round(100 * len(resolved) / len(with_runs), 1) if with_runs else None,
        len(with_runs), "%")

    hi = [r for _, r in runs if float(r.get("confidence", 0) or 0) >= 0.85]
    out["high_confidence_rca_rate"] = metric(
        round(100 * len(hi) / len(runs), 1) if runs else None, len(runs), "%")

    with_fix = {p.get("incident_id") for p in prs if p.get("incident_id")}
    out["pr_creation_rate"] = metric(
        round(100 * len(with_fix) / len(with_runs), 1) if with_runs else None,
        len(with_runs), "%")

    passed = [p for p in prs if str(p.get("tests_status", "")).lower() == "passed"]
    out["fix_validation_rate"] = metric(
        round(100 * len(passed) / len(prs), 1) if prs else None, len(prs), "%")

    pairs: Dict[str, int] = {}
    for m in memories:
        pairs[f"{m.get('service')}|{m.get('root_cause_category')}"] = \
            pairs.get(f"{m.get('service')}|{m.get('root_cause_category')}", 0) + 1
    repeat = sum(1 for m in memories
                 if pairs.get(f"{m.get('service')}|{m.get('root_cause_category')}", 0) > 1)
    out["repeat_incident_recognition_rate"] = metric(
        round(100 * repeat / len(memories), 1) if memories else None,
        len(memories), "%")
    return out
