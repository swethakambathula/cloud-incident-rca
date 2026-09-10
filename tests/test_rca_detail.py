"""
RCA detail tests: timeline parsing/grouping, raw evidence, policy disclosure,
rejection-comment enforcement, structured remediation contract.
"""
import os

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tools.timeline_view import group_events, humanize_enum, parse_event, significant


@pytest.fixture(scope="module")
def live_incident():
    c = TestClient(app)
    c.post("/api/simulate/pool-exhaustion")
    iid = c.post("/api/rca/live").json()["incident_id"]
    return c, iid


def test_parse_event_extracts_code_and_attributes():
    parsed = parse_event("ERROR: DATABASE_CONNECTION_POOL_EXHAUSTED "
                         "pool_usage=100% active=50 max=50 waiting_threads=45")
    assert parsed["title"] == "Database Connection Pool Exhausted"
    assert parsed["error_code"] == "DATABASE_CONNECTION_POOL_EXHAUSTED"
    assert parsed["attributes"]["pool_usage"] == "100%"
    assert parsed["attributes"]["waiting_threads"] == "45"
    assert "pool_usage" in parsed["raw"]


def test_humanize_enum_display_only():
    assert humanize_enum("CONNECTION_POOL_EXHAUSTION") == "Connection Pool Exhaustion"
    assert humanize_enum("WAITING_APPROVAL") == "Waiting for Approval"
    assert humanize_enum("") == ""
    assert humanize_enum("ALLOWED_WITH_APPROVAL") == "Allowed With Approval"
    assert humanize_enum("DATABASE_CONNECTION_POOL_EXHAUSTED") == "Database Connection Pool Exhausted"


def test_group_collapses_repeats_with_range_and_peaks():
    events = [{"timestamp": f"2026-09-10T20:23:{53 + i * 4:02d}Z",
               "event_type": "ERROR_SPIKE",
               "description": "DATABASE_CONNECTION_POOL_EXHAUSTED pool_usage=100% waiting_threads=45",
               "source": "logging"} for i in range(4)]
    groups = group_events(events)
    assert len(groups) == 1
    group = groups[0]
    assert group["count"] == 4
    assert group["first"] < group["last"]
    assert group["attributes"]["waiting_threads"] == "45"
    assert group["title"] == "Database Connection Pool Exhausted"


def test_significant_keeps_milestones_plus_groups():
    events = [
        {"timestamp": "2026-09-10T14:30:00Z", "event_type": "LATENCY_INCREASE",
         "description": "p95 latency rose", "source": "monitoring"},
        {"timestamp": "2026-09-10T14:30:53Z", "event_type": "ERROR_SPIKE",
         "description": "DATABASE_CONNECTION_POOL_EXHAUSTED pool_usage=100%", "source": "logging"},
        {"timestamp": "2026-09-10T14:30:57Z", "event_type": "ERROR_SPIKE",
         "description": "DATABASE_CONNECTION_POOL_EXHAUSTED pool_usage=100%", "source": "logging"},
    ]
    view = significant(events)
    kinds = [e["kind"] for e in view]
    assert kinds == ["event", "group"]
    assert view[1]["count"] == 2


def test_timeline_endpoint_grouped_and_all(live_incident):
    c, iid = live_incident
    sig = c.get(f"/api/incidents/{iid}/timeline").json()
    assert sig["view"] == "significant" and sig["total_events"] > 0
    assert any(g["count"] >= 1 for g in sig["groups"])
    for g in sig["groups"]:
        assert {"key", "title", "count", "first", "last", "attributes"} <= set(g)
    everything = c.get(f"/api/incidents/{iid}/timeline?view=all").json()
    assert everything["view"] == "all"
    assert len(everything["events"]) == sig["total_events"]
    assert c.get("/api/incidents/NOPE/timeline").status_code == 404


def test_raw_evidence_endpoint_shape(live_incident):
    c, iid = live_incident
    raw = c.get(f"/api/incidents/{iid}/evidence/raw?limit=5").json()
    for key in ("raw_logs", "application_errors", "request_errors", "metrics",
                "recent_deployments", "traces", "dependencies", "agent_findings"):
        assert key in raw
    assert len(raw["raw_logs"]) <= 5
    assert c.get("/api/incidents/NOPE/evidence/raw").status_code == 404


def test_propose_discloses_policy_and_contract(live_incident):
    c, iid = live_incident
    body = c.post(f"/api/incidents/{iid}/remediation/propose").json()
    assert body["policy"] in ("READ_ONLY", "ALLOWED_WITH_APPROVAL", "DISALLOWED")
    plan = body["remediation_plan"]
    for key in ("recommended_action", "mitigation_type", "estimated_risk",
                "expected_effect", "rollback_plan", "verification_plan",
                "required_permissions", "preconditions"):
        assert key in plan, f"missing {key}"


def test_rejection_requires_comment(live_incident):
    c, iid = live_incident
    aid = c.post(f"/api/incidents/{iid}/remediation/propose").json()["approval"]["approval_id"]
    assert c.post(f"/api/approvals/{aid}/reject", json={}).status_code == 400
    assert c.post(f"/api/approvals/{aid}/reject").status_code == 400
    ok = c.post(f"/api/approvals/{aid}/reject", json={"message": "not now"}).json()
    assert ok["status"] == "REJECTED"


@pytest.fixture()
def demo_repo(tmp_path, monkeypatch):
    import shutil
    import subprocess
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "cloud-rca-demo-app")
    repo = str(tmp_path / "demo")
    shutil.copytree(src, repo, ignore=shutil.ignore_patterns("__pycache__"))
    subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "rca@test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "rca-test"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init faulty"], cwd=repo, check=True, capture_output=True)
    bare = str(tmp_path / "origin.git")
    subprocess.run(["git", "init", "--bare", bare], check=True, capture_output=True)
    subprocess.run(["git", "remote", "add", "origin", bare], cwd=repo, check=True)
    subprocess.run(["git", "push", "-u", "origin", "main"], cwd=repo, check=True, capture_output=True)
    monkeypatch.setenv("DEMO_APP_PATH", repo)
    return repo


def test_fix_rejection_requires_comment(live_incident, demo_repo):
    c, iid = live_incident
    c.post(f"/api/incidents/{iid}/generate-fix")
    assert c.post(f"/api/incidents/{iid}/fix/reject", json={}).status_code == 400
