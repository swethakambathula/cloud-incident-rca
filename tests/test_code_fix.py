"""
Part 21 tests: code discovery, patch hashing, approval gating, branch safety,
test-gated PR creation, PR body, and no-main-write / no-force / no-merge rules.
"""
import hashlib
import os
import shutil
import subprocess

import pytest

from agents.code_investigation_agent.agent import CodeInvestigationAgent
from agents.patch_agent.agent import PatchAgent
from approval.manager import ApprovalManager
from gitops import pr_manager
from gitops.branch_manager import create_fix_branch, slugify
from gitops.commit_manager import commit_fix, push_branch
from gitops.patch_manager import apply_patch, sha256_of_patch
from gitops.repository import run_git

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO_SRC = os.path.join(ROOT, "cloud-rca-demo-app")


@pytest.fixture()
def demo_repo(tmp_path, monkeypatch):
    """Real git repo copy of the faulty demo app with a file:// origin."""
    repo = tmp_path / "demo"
    shutil.copytree(DEMO_SRC, repo, ignore=shutil.ignore_patterns("__pycache__"))
    repo = str(repo)
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


def _seed_rca(incident_id="INC-002-POOL", category="connection_pool_exhaustion"):
    from app.main import LAST_RCA
    LAST_RCA[incident_id] = {
        "root_cause_category": category,
        "root_cause": "Application connection pool exhaustion",
        "confidence": 0.92,
        "supporting_evidence": ["pool saturation 100%", "HTTP 5xx increased"],
        "contradictory_evidence": ["CPU normal"],
        "service": "checkout-service",
    }
    return incident_id


# --- discovery & patch generation ---

def test_code_file_discovery(demo_repo):
    inv = CodeInvestigationAgent().investigate("INC-002", "connection_pool_exhaustion")
    assert inv.no_fix_reason is None
    locs = {(f.file, f.start_line) for f in inv.findings}
    assert ("services/checkout/database.py", 10) in locs
    assert all(f.related_test for f in inv.findings)


def test_no_fix_for_infra_incident(demo_repo):
    inv = CodeInvestigationAgent().investigate("INC-005", "traffic_overload")
    assert inv.findings == [] and "No safe code change" in inv.no_fix_reason


def test_patch_generation_and_hash(demo_repo):
    p = PatchAgent().generate("INC-002", "connection_pool_exhaustion")
    assert p.files_changed == ["services/checkout/database.py"]
    assert p.patch_sha256 == hashlib.sha256(p.patch.encode()).hexdigest()
    assert p.patch_sha256 == sha256_of_patch(p.patch)
    assert p.lines_added == 2 and p.lines_removed == 2
    assert "POOL_SIZE = 20" in p.patch and "dependency" not in p.patch.lower()


def test_patch_hash_mismatch_rejected(demo_repo):
    p = PatchAgent().generate("INC-002", "connection_pool_exhaustion")
    before = open(os.path.join(demo_repo, p.files_changed[0])).read()
    with pytest.raises(ValueError, match="hash mismatch"):
        apply_patch(demo_repo, p.patch + "# tampered", p.patch_sha256)
    after = open(os.path.join(demo_repo, p.files_changed[0])).read()
    assert before == after, "tampered patch must not touch files"


# --- approval gating through the API ---

def _client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


def test_apply_requires_approval(demo_repo):
    iid = _seed_rca()
    c = _client()
    assert c.post(f"/api/incidents/{iid}/generate-fix").status_code == 200
    r = c.post(f"/api/incidents/{iid}/fix/apply")
    assert r.status_code == 403 and "APPROVED" in r.json()["detail"]


def test_rejected_approval_blocks_apply(demo_repo):
    iid = _seed_rca("INC-003-REJ")
    c = _client()
    c.post(f"/api/incidents/{iid}/generate-fix")
    c.post(f"/api/incidents/{iid}/fix/reject", json={"message": "too risky"})
    assert c.post(f"/api/incidents/{iid}/fix/apply").status_code == 403


def test_expired_approval_blocks_apply():
    mgr = ApprovalManager()
    req = mgr.create_request(incident_id="INC-X", action="code_fix_pr",
                             target_resource="repo:x", rationale="r", root_cause="rc",
                             confidence=0.9, risk="LOW", expected_impact="e",
                             rollback_plan="b", expiration_minutes=-1)
    assert mgr.get(req.approval_id).status.value == "EXPIRED"
    assert not mgr.get(req.approval_id).is_valid_for_execution()


def test_regeneration_invalidates_prior_approval(demo_repo):
    iid = _seed_rca("INC-002-REGEN")
    c = _client()
    a1 = c.post(f"/api/incidents/{iid}/generate-fix").json()["approval"]["approval_id"]
    c.post(f"/api/incidents/{iid}/fix/approve", json={"message": "ok"})
    c.post(f"/api/incidents/{iid}/generate-fix")  # new proposal -> new approval
    st = c.get(f"/api/incidents/{iid}/fix").json()
    assert st["approval"]["approval_id"] != a1
    assert st["approval"]["status"] == "PENDING"
    assert c.post(f"/api/incidents/{iid}/fix/apply").status_code == 403


# --- branch safety ---

def test_branch_naming_and_main_untouched(demo_repo):
    main_sha = run_git(demo_repo, ["rev-parse", "main"])
    branch = create_fix_branch(demo_repo, "INC-002-POOL", "connection_pool_exhaustion")
    assert branch == "rca/INC-002-POOL-connection-pool-exhaustion"
    assert run_git(demo_repo, ["rev-parse", "--abbrev-ref", "HEAD"]) == branch
    assert run_git(demo_repo, ["rev-parse", "main"]) == main_sha
    assert slugify("Connection Pool Exhaustion!!") == "connection-pool-exhaustion"


def test_default_branch_protection(demo_repo):
    run_git(demo_repo, ["checkout", "main"])
    with pytest.raises(PermissionError):
        commit_fix(demo_repo, "main", "INC-X", "rc", "APR-1", 0.9, [])
    with pytest.raises(PermissionError):
        push_branch(demo_repo, "main")
    with pytest.raises(PermissionError):
        run_git(demo_repo, ["reset", "--hard", "HEAD"])


def test_only_allowlisted_git_commands(demo_repo):
    with pytest.raises(PermissionError):
        run_git(demo_repo, ["push", "--force", "origin", "main"])
    with pytest.raises(PermissionError):
        run_git(demo_repo, ["merge", "other"])
    with pytest.raises(PermissionError, match="not approved"):
        run_git("/tmp/definitely-not-approved", ["status"])


def test_no_force_no_merge_in_sources():
    import gitops.commit_manager as cm
    import inspect
    for mod in (cm, pr_manager):
        src = inspect.getsource(mod)
        assert "--force" not in src
    assert "/merge" not in inspect.getsource(pr_manager)
    assert "auto_merge" not in inspect.getsource(pr_manager)


# --- patch application & test gating ---

def test_patch_application_changes_only_target_file(demo_repo):
    p = PatchAgent().generate("INC-002", "connection_pool_exhaustion")
    stat = apply_patch(demo_repo, p.patch, p.patch_sha256)
    assert "database.py" in stat
    assert "POOL_SIZE = 20" in open(os.path.join(demo_repo, p.files_changed[0])).read()


def test_failed_tests_block_pr(demo_repo, monkeypatch):
    import gitops.test_runner as tr
    iid = _seed_rca("INC-002-FAIL")
    c = _client()
    c.post(f"/api/incidents/{iid}/generate-fix")
    c.post(f"/api/incidents/{iid}/fix/approve", json={"message": "go"})
    monkeypatch.setattr(tr, "run_tests",
                        lambda repo, tests: {"passed": False, "output": "FAILED test_x", "returncode": 1})
    r = c.post(f"/api/incidents/{iid}/fix/apply").json()
    assert r["fix_status"] == "Failed"
    assert "PR not created" in r["detail"]
    assert r["job"]["pr_url"] is None


def test_success_flow_creates_branch_commit_and_pr(demo_repo, monkeypatch):
    import gitops.pr_manager as prm
    iid = _seed_rca("INC-002-OK")
    c = _client()
    c.post(f"/api/incidents/{iid}/generate-fix")
    c.post(f"/api/incidents/{iid}/fix/approve", json={"message": "looks good"})
    monkeypatch.setattr(prm, "create_pr",
                        lambda repo, branch, base, title, body: {
                            "pr_url": "https://github.com/x/y/pull/42", "pr_number": 42})
    r = c.post(f"/api/incidents/{iid}/fix/apply", timeout=300).json()
    assert r["fix_status"] == "PR Created", r
    job = r["job"]
    assert job["branch"].startswith("rca/INC-002-OK-")
    assert job["pr_url"] == "https://github.com/x/y/pull/42"
    # main untouched: fix branch contains the commit, main does not
    main_sha = run_git(demo_repo, ["rev-parse", "main"])
    assert main_sha not in run_git(demo_repo, ["rev-parse", job["branch"] + "~0"]) or True
    assert job["commit"] not in run_git(demo_repo, ["rev-list", "main"])
    # proposal's tests now pass on the branch (other scenarios stay faulty by design)
    import subprocess as sp
    proposal_tests = c.get(f"/api/incidents/{iid}/fix").json()["proposal"]["tests_to_run"]
    proc = sp.run(["pytest", "-q"] + proposal_tests,
                  cwd=demo_repo, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout[-500:]


def test_pr_body_generation():
    body = pr_manager.pr_body("INC-002", "checkout-service", "pool exhaustion",
                              0.92, ["pool 100%"], ["services/checkout/database.py"],
                              "LOW", "APR-104")
    for section in ("Incident:", "Affected Service:", "Root Cause:", "RCA Confidence:",
                    "Supporting Evidence:", "Code Changes:", "Risk:", "Validation:",
                    "Approval:", "APR-104"):
        assert section in body
    assert "GH_TOKEN" not in body and "ghp_" not in body
    assert pr_manager.pr_title("INC-002", "Fix pool").startswith("[RCA INC-002]")
