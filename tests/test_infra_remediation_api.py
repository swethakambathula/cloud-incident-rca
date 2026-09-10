"""
Infra remediation API tests: explicit propose -> suggested params -> approve ->
execute & verify. Nothing is auto-created by RCA.
"""
from fastapi.testclient import TestClient
from app.main import app


def _client():
    return TestClient(app)


def _pending_for(c, incident_id):
    return [a for a in c.get("/api/approvals/pending").json()
            if a["incident_id"] == incident_id]


def test_rca_creates_nothing_explicit_propose_creates_one():
    c = _client()
    c.post("/api/simulate/pool-exhaustion")
    iid = c.post("/api/rca/live").json()["incident_id"]
    assert _pending_for(c, iid) == []
    assert c.post("/api/incidents/NOPE/remediation/propose").status_code == 400

    p = c.post(f"/api/incidents/{iid}/remediation/propose").json()
    assert p["remediation_plan"]["recommended_action"] == "cloud_run_scale_within_limits"
    assert p["approval"]["status"] == "PENDING"
    assert p["suggested_params"] == {"max_instances": 10}
    assert len(_pending_for(c, iid)) == 1


def test_scale_execute_and_verify():
    c = _client()
    c.post("/api/simulate/pool-exhaustion")
    iid = c.post("/api/rca/live").json()["incident_id"]
    aid = c.post(f"/api/incidents/{iid}/remediation/propose").json()["approval"]["approval_id"]

    params = c.get(f"/api/approvals/{aid}/params").json()
    assert params["params"] == {"max_instances": 10}

    # execute without approval -> BLOCKED, never SUCCESS
    blocked = c.post(f"/api/approvals/{aid}/execute", json={"max_instances": 5}).json()
    assert blocked["execution"]["status"] == "BLOCKED"

    c.post(f"/api/approvals/{aid}/approve", json={"message": "scale for overload"})
    done = c.post(f"/api/approvals/{aid}/execute", json={"max_instances": 5}).json()
    ex, vf = done["execution"], done["verification"]
    assert ex["status"] == "SUCCESS", ex
    assert ex["before_state"] and ex["after_state"]
    assert ex["rollback_available"] is True
    assert vf["verification_status"] in ("RESOLVED", "PARTIALLY_RESOLVED", "NOT_RESOLVED",
                                         "REGRESSED", "INSUFFICIENT_DATA")
    assert "error_rate_before" in vf and "latency_after" in vf
    assert done["postmortem"]


def test_rollback_revision_choices_and_selected_execute():
    c = _client()
    c.post("/api/simulate/bad-deployment")
    iid = c.post("/api/rca/live").json()["incident_id"]
    aid = c.post(f"/api/incidents/{iid}/remediation/propose").json()["approval"]["approval_id"]

    choices = c.get(f"/api/approvals/{aid}/revisions").json()
    assert len(choices["revisions"]) >= 2
    current = [r for r in choices["revisions"] if r["is_current"]]
    previous = [r for r in choices["revisions"] if not r["is_current"]]
    assert len(current) == 1 and len(previous) >= 1
    assert choices["suggested"] == previous[0]["revision_name"]
    assert all("deployed_at" in r for r in choices["revisions"])

    c.post(f"/api/approvals/{aid}/approve", json={"message": "rollback to selected"})
    done = c.post(f"/api/approvals/{aid}/execute",
                  json={"target_revision": choices["suggested"]}).json()
    assert done["execution"]["status"] == "SUCCESS", done["execution"]
    assert choices["suggested"] in str(done["execution"]["after_state"])


def test_live_traffic_endpoint_reports_split():
    c = _client()
    c.post("/api/simulate/pool-exhaustion")
    iid = c.post("/api/rca/live").json()["incident_id"]
    aid = c.post(f"/api/incidents/{iid}/remediation/propose").json()["approval"]["approval_id"]
    t = c.get(f"/api/approvals/{aid}/live-traffic").json()
    assert t["service"] == "checkout-service"
    assert isinstance(t["traffic_split"], dict) and len(t["traffic_split"]) >= 1
    assert sum(t["traffic_split"].values()) == 100
    assert c.get("/api/approvals/NOPE/live-traffic").status_code == 404


def test_rollback_suggests_previous_revision():
    c = _client()
    c.post("/api/simulate/bad-deployment")
    iid = c.post("/api/rca/live").json()["incident_id"]
    p = c.post(f"/api/incidents/{iid}/remediation/propose").json()
    assert p["remediation_plan"]["recommended_action"] == "cloud_run_rollback"
    target = p["suggested_params"].get("target_revision")
    assert target, "rollback should suggest a previous revision"
    assert target != "checkout-service-00005-bad"
