"""
UX platform tests: taxonomy, projects/onboarding, incidents lifecycle,
uploads + file RCA, PR registry, home stats, export gating.
"""
import io
import json
import os

import pytest
from fastapi.testclient import TestClient

from app.main import app
from orchestration.incident_registry import IncidentRegistry
from projects.store import ProjectStore, PRRegistry
from schemas.project import PullRequestRecord
from tools.error_taxonomy import domain_for_category, domain_for_scenario, GROUPS


def _client():
    return TestClient(app)


@pytest.fixture()
def demo_repo(tmp_path, monkeypatch):
    """Isolated git checkout of the demo app with a file:// origin."""
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


@pytest.fixture()
def demo_repo(tmp_path, monkeypatch):
    """Isolated git checkout of the demo app with a file:// origin."""
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


def test_generate_refuses_non_repo_path(tmp_path, monkeypatch):
    """Parent-repo protection: a plain directory must never be git-operated on."""
    import shutil
    plain = str(tmp_path / "plain")
    shutil.copytree(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                 "cloud-rca-demo-app"),
                    plain, ignore=shutil.ignore_patterns("__pycache__", ".git"))
    monkeypatch.setenv("DEMO_APP_PATH", plain)
    c = _client()
    c.post("/api/simulate/pool-exhaustion")
    iid = c.post("/api/rca/live").json()["incident_id"]
    r = c.post(f"/api/incidents/{iid}/generate-fix")
    assert r.status_code == 409
    assert "git checkout" in r.json()["detail"].lower()


def test_taxonomy_endpoint_and_maps():
    c = _client()
    body = c.get("/api/taxonomy").json()
    assert body["scenarios"]["pool-exhaustion"] == {
        "domain": "Code / Application", "subcategory": "Application Resource"}
    assert body["scenarios"]["traffic-overload"]["domain"] == "Infrastructure / Platform"
    assert set(body["groups"]) == {"code", "infra"}
    assert domain_for_category("faulty_revision")[0] == "Code / Application"
    assert domain_for_category("nope") == ("Unknown", "Unknown")
    assert domain_for_scenario("rate-limit") == ("Infrastructure / Platform", "Quota")


def test_project_lifecycle(tmp_path, monkeypatch):
    from projects import store as store_mod
    db = tmp_path / "projects.json"
    monkeypatch.setattr(store_mod, "PROJECTS_FILE", str(db))
    ps = ProjectStore(path=str(db))
    assert any(p.project_id == "checkout-platform" for p in ps.list())
    assert ps.resolve_project("checkout-service") == "checkout-platform"
    assert ps.resolve_project("nope") == "unassigned"

    c = _client()
    created = c.post("/api/projects", json={"name": "Triage"}).json()
    assert created["project_id"] == "triage"
    assert c.post("/api/projects", json={"name": ""}).status_code == 400

    scan = c.post(f"/api/projects/{created['project_id']}/scan").json()
    assert "scan" in scan  # missing local path -> error payload, still 200

    conn = c.post(f"/api/projects/{created['project_id']}/test-connection",
                  json={"kind": "git", "local_path": "definitely-not-here"}).json()
    assert conn["ok"] is False
    assert c.post("/api/projects/nope/test-connection", json={"kind": "git"}).status_code == 404

    # onboard wizard against the real demo app copy
    demo = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "cloud-rca-demo-app")
    onboarded = c.post("/api/projects/onboard", json={
        "name": "Demo Scan", "local_path": demo,
        "services": [], "environment": "dev"}).json()
    assert onboarded["readiness"]["rca_ready"] is True
    assert "python" in onboarded["scan"]["languages"]
    assert onboarded["project"]["data_sources"]

    disc = c.post(f"/api/projects/{created['project_id']}/disconnect",
                  json={"kind": "git"}).json()
    assert all(s["kind"] != "git" for s in disc["data_sources"])


def test_incident_lifecycle_and_invalid_transitions():
    reg = IncidentRegistry(path=":memory:") if False else None
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        from orchestration import incident_registry as reg_mod
        reg = reg_mod.IncidentRegistry(path=os.path.join(tmp, "i.json"))
        rec = reg.ensure("INC-T1", title="t", services=["s"])
        assert rec["status"] == "NEW"
        reg.transition("INC-T1", "COLLECTING_EVIDENCE")
        with pytest.raises(ValueError):
            reg.transition("INC-T1", "RESOLVED")  # skipped states rejected
        with pytest.raises(ValueError):
            reg.transition("INC-T1", "NOPE")
        reg.transition("INC-T1", "ANALYZING")
        reg.transition("INC-T1", "ROOT_CAUSE_IDENTIFIED")
        assert reg.get("INC-T1")["status"] == "ROOT_CAUSE_IDENTIFIED"
        reg.add_note("INC-T1", "op", "hello")
        assert reg.get("INC-T1")["notes"][0]["text"] == "hello"


def test_manual_incident_api_and_notes():
    c = _client()
    assert c.post("/api/projects/nope/incidents", json={"title": "x"}).status_code == 404
    assert c.post("/api/projects/checkout-platform/incidents", json={"title": ""}).status_code == 400
    created = c.post("/api/projects/checkout-platform/incidents", json={
        "title": "Manual spike", "severity": "critical",
        "affected_services": ["checkout-service"], "description": "500s everywhere",
        "error_signature": "DATABASE_CONNECTION_TIMEOUT"}).json()
    assert created["incident_id"].startswith("INC-MANUAL-SPIKE")
    assert created["status"] == "NEW"
    notes = c.post(f"/api/incidents/{created['incident_id']}/notes",
                   json={"author": "op", "text": "paging"}).json()
    assert notes["notes"][0]["text"] == "paging"
    assert c.post(f"/api/incidents/{created['incident_id']}/notes",
                  json={"text": ""}).status_code == 400
    # manual RCA runs from stored inputs (slower path, one run)
    rca = c.post("/api/rca/live", json={"incident_id": created["incident_id"]}).json()
    assert rca["root_cause_category"] == "database_connectivity"
    assert rca["evidence_source"] == "manual"
    detail = c.get(f"/api/incidents/{created['incident_id']}").json()
    assert len(detail["rca_runs"]) >= 1
    assert detail["rca_runs"][-1]["evidence_source"] == "manual"


def test_upload_preview_and_validation():
    c = _client()
    txt = ("2026-09-10T10:20:04Z ERROR checkout-service DATABASE_CONNECTION_TIMEOUT "
           "could not connect to orders-db:5432 after 5000ms trace_id=abc12345\n"
           "2026-09-10T10:20:09Z INFO checkout-service request completed 200\n")
    r = c.post("/api/logs/upload",
               data={"project_id": "checkout-platform", "source_type": "Auto Detect"},
               files=[("files", ("checkout.log", io.BytesIO(txt.encode()), "text/plain"))])
    assert r.status_code == 200
    body = r.json()
    assert body["files"][0]["detected_format"] == "text"
    assert body["files"][0]["record_count"] == 2
    assert body["preview_stats"]["services"] == ["checkout-service"]
    assert body["preview_stats"]["error_codes"] == ["DATABASE_CONNECTION_TIMEOUT"]

    bad = c.post("/api/logs/upload", data={},
                 files=[("files", ("evil.exe", b"xx", "application/octet-stream"))])
    assert bad.json()["files"][0]["parse_status"] == "rejected"

    js = c.post("/api/logs/upload", data={},
                files=[("files", ("a.jsonl",
                                  b'{"severity":"ERROR","service":"orders-service","status_code":503,"error_code":"DOWNSTREAM_TIMEOUT"}\n',
                                  "application/json"))]).json()
    assert js["files"][0]["detected_format"] == "jsonl"

    csv_body = ("timestamp,severity,service,status_code,latency_ms,error_code,message\n"
                "2026-09-10T10:20:00Z,ERROR,checkout-service,500,5020,DATABASE_CONNECTION_TIMEOUT,db down\n")
    csv = c.post("/api/logs/upload", data={},
                 files=[("files", ("m.csv", io.BytesIO(csv_body.encode()), "text/csv"))]).json()
    assert csv["files"][0]["detected_format"] == "csv"
    assert csv["preview_stats"]["record_count"] == 1


def test_file_rca_flow_and_history():
    c = _client()
    txt = "".join(
        f"2026-09-10T10:20:{i:02d}Z ERROR checkout-service DATABASE_CONNECTION_TIMEOUT "
        f"could not connect trace_id=trace-{i}\n" for i in range(8))
    up = c.post("/api/logs/upload", data={"project_id": "checkout-platform"},
                files=[("files", ("db.log", io.BytesIO(txt.encode()), "text/plain"))]).json()
    aid = up["analysis_id"]
    result = c.post(f"/api/logs/{aid}/analyze", timeout=300).json()
    assert result["evidence_source"] == "upload"
    assert result["root_cause_category"] == "database_connectivity"
    assert len(result["supporting_evidence"]) > 0
    assert len(result["timeline"]) > 0
    assert result["record_count"] == 8
    assert result["domain"] == "Code / Application"
    assert c.post("/api/logs/NOPE/analyze").status_code == 404
    history = c.get("/api/log-analyses").json()
    assert any(a["analysis_id"] == aid and a["status"] == "analyzed" for a in history)
    detail = c.get(f"/api/log-analyses/{aid}").json()
    assert detail["rca"]["incident_id"].startswith("INC-UPLOAD-")


def test_pr_record_persists_diff(demo_repo, monkeypatch):
    """End-to-end hook check: recorded PR must carry the exact proposed diff."""
    import gitops.pr_manager as prm
    monkeypatch.setattr(prm, "create_pr",
                        lambda repo, branch, base, title, body: {
                            "pr_url": "https://github.com/x/y/pull/99", "pr_number": 99})
    iid = _seed_rca("INC-DIFF-REG")
    c = _client()
    c.post(f"/api/incidents/{iid}/generate-fix")
    c.post(f"/api/incidents/{iid}/fix/approve", json={"message": "ok"})
    assert c.post(f"/api/incidents/{iid}/fix/apply", timeout=300).json()["fix_status"] == "PR Created"
    from projects.store import PRRegistry
    recs = PRRegistry().by_incident(iid)
    assert len(recs) >= 1
    assert all(len(r.diff) > 0 and "POOL_SIZE" in r.diff for r in recs)


def _seed_rca(incident_id, category="connection_pool_exhaustion"):
    from app.main import LAST_RCA
    LAST_RCA[incident_id] = {
        "root_cause_category": category, "root_cause": "pool", "confidence": 0.9,
        "supporting_evidence": ["a"], "contradictory_evidence": [], "service": "checkout-service"}
    return incident_id


def test_pr_registry_and_filters(tmp_path, monkeypatch):
    from projects import store as store_mod
    db = tmp_path / "prs.jsonl"
    monkeypatch.setattr(store_mod, "PRS_FILE", str(db))
    reg = PRRegistry(path=str(db))
    reg.record(PullRequestRecord(
        pr_id="PR-42", pr_number=42, project_id="checkout-platform",
        incident_id="INC-002", repository="demo/app", branch="rca/x",
        base_branch="main", commit_sha="abc", title="Fix pool",
        root_cause="pool", root_cause_category="connection_pool_exhaustion",
        confidence=0.9, risk="LOW", status="Open", tests_status="passed",
        created_by="rca-agent", external_url="https://example.com/pr/42"))
    reg.record(PullRequestRecord(
        pr_id="PR-43", pr_number=43, project_id="other",
        incident_id="INC-9", repository="demo/app", branch="rca/y",
        title="Fix z", root_cause="z", confidence=0.5, created_by="rca-agent"))
    assert len(reg.list()) == 2
    assert [r.pr_id for r in reg.list(project_id="checkout-platform")] == ["PR-42"]
    assert reg.get("PR-42").external_url.endswith("/pr/42")
    assert reg.by_incident("INC-002")[0].pr_number == 42
    assert reg.get("NOPE") is None


def test_homepage_shell_and_terminology():
    c = _client()
    html = c.get("/").text
    for token in ["view-home", "view-projects", "view-prs", "topnav",
                  "Approval Center", "Approval & Action History", "Analyze Logs"]:
        assert token in html, f"missing {token}"
    assert "Phase 4" not in html
    for view in ["home", "projects", "incidents", "prs", "analyze", "settings"]:
        assert f"data-view=\"{view}\"" in html or f"go('{view}')" in html


def test_home_stats_and_export_gating():
    c = _client()
    stats = c.get("/api/home/stats").json()
    for key in ("projects", "open_incidents", "rca_completed", "prs_awaiting_approval",
                "prs_created", "pending_approvals", "recent_activity", "recent_prs",
                "recent_incidents"):
        assert key in stats
    assert stats["projects"] >= 1
    assert c.get("/api/incidents/NOPE/export").status_code == 404
    assert c.get("/api/pull-requests/NOPE").status_code == 404
    meta = c.get("/api/incidents/meta").json()
    assert any(m["incident_id"] == "INC-003-BAD-DEPLOYMENT" for m in meta)
    bad = next(m for m in meta if m["incident_id"] == "INC-003-BAD-DEPLOYMENT")
    assert bad["project_id"] == "checkout-platform"


def test_pr_requires_approved_fix(demo_repo):
    """Critical: no PR record may exist without an APPROVED code-change approval."""
    c = _client()
    c.post("/api/simulate/pool-exhaustion")
    iid = c.post("/api/rca/live").json()["incident_id"]
    c.post(f"/api/incidents/{iid}/generate-fix")
    # apply while still PENDING -> 403, and no PR recorded
    assert c.post(f"/api/incidents/{iid}/fix/apply").status_code == 403
    assert c.get(f"/api/incidents/{iid}/pr").json()["pr_url"] is None
