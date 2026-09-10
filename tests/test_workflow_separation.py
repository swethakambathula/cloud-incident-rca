"""Separated workflows: MANUAL vs SIMULATION vs LOG_UPLOAD.

Covers: source persistence, simulation isolation, attachment dedup/linkage,
repo unavailable/mapping behavior, stack-trace extraction + exact targeting,
code finding + fix generation, simulation ground truth, analyze-only mode
and conversion, plus end-to-end REAL and SIMULATION flows.
"""
import io
import json
import os

from fastapi.testclient import TestClient

from app.main import app
from orchestration.incident_registry import IncidentRegistry
from orchestration.attachments import AttachmentStore
from schemas.incident_source import IncidentSource

client = TestClient(app)
PID = "checkout-platform"


def _mk_project(tmp_path=None):
    r = client.get(f"/api/projects/{PID}")
    assert r.status_code == 200, r.text
    return r.json()


def test_manual_incident_source_persisted():
    r = client.post(f"/api/projects/{PID}/incidents", json={"title": "Manual sep test"})
    assert r.status_code == 200, r.text
    iid = r.json()["incident_id"]
    assert r.json()["source"] == IncidentSource.MANUAL.value
    d = client.get(f"/api/incidents/{iid}").json()
    assert d["source"] == "MANUAL"
    assert d["is_simulation"] is False


def test_simulation_always_creates_new_incident():
    a = client.post("/api/simulations/run", json={"scenario": "null-pointer", "environment": "demo"}).json()
    b = client.post("/api/simulations/run", json={"scenario": "null-pointer", "environment": "demo"}).json()
    assert a["incident_id"] != b["incident_id"]
    assert a["source"] == "SIMULATION" and b["source"] == "SIMULATION"
    assert a["incident_id"].startswith("INC-SIM-")


def test_simulation_cannot_mutate_manual_incident():
    r = client.post(f"/api/projects/{PID}/incidents", json={"title": "Real must stay clean"})
    iid = r.json()["incident_id"]
    regen = client.post(f"/api/simulations/{iid}/regenerate")
    assert regen.status_code == 409
    # run simulation -> different incident, real one untouched
    sim = client.post("/api/simulations/run", json={"scenario": "null-pointer", "environment": "demo"}).json()
    assert sim["incident_id"] != iid
    det = client.get(f"/api/incidents/{iid}").json()
    assert det["source"] == "MANUAL"


def test_simulation_prod_blocked():
    r = client.post("/api/simulations/run", json={"scenario": "null-pointer", "environment": "production"})
    assert r.status_code == 400


def test_log_attachments_linked_and_deduped(tmp_path):
    store = AttachmentStore(path=str(tmp_path / "att.json"))
    rec = store.attach("INC-X", PID, "checkout-errors.log", b"ERROR boom\n", "text/plain")
    assert rec["incident_id"] == "INC-X" and rec["parsed_event_count"] >= 0
    try:
        store.attach("INC-X", PID, "checkout-errors.log", b"ERROR boom\n", "text/plain")
        assert False, "duplicate should raise"
    except ValueError as e:
        assert "already attached" in str(e)


def test_repo_readiness_and_mapping():
    r = client.get(f"/api/projects/{PID}/repo-readiness")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] in ("Repository Ready", "Repository Needs Attention")
    assert any(c["check"] == "repository_reachable" for c in body["checks"])
    m = client.put(f"/api/projects/{PID}/repo-mapping",
                   json={"service_mappings": {"checkout-service": "services/checkout/"}})
    assert m.status_code == 200
    assert m.json()["service_mappings"]["checkout-service"] == "services/checkout/"


def test_stack_trace_extraction_python_and_java():
    from tools.stacktrace import extract_stack_trace, primary_suspect
    py = ('Traceback (most recent call last):\n'
          '  File "services/checkout/payment_processor.py", line 24, in process_payment\n'
          "    amount = payment_profile.amount\n"
          "AttributeError: 'NoneType' object has no attribute 'amount'")
    p = extract_stack_trace(py)
    assert p["language"] == "python" and p["exception_type"] == "AttributeError"
    s = primary_suspect(p)
    assert s["file"].endswith("payment_processor.py") and s["line"] == 24
    jv = "NullPointerException in PaymentProcessor.java:84 at checkout-service-00005-bad\n\tat com.shop.PaymentProcessor.charge(PaymentProcessor.java:84)"
    j = extract_stack_trace(jv)
    assert j["frames"] and j["frames"][0]["file"] == "PaymentProcessor.java"


def test_exact_file_targeting():
    from tools.code_search import search_code
    from tools.stacktrace import extract_stack_trace
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cloud-rca-demo-app")
    stack = extract_stack_trace('File "services/checkout/payment_processor.py", line 24, in process_payment\nAttributeError: x')
    res = search_code(root, service="checkout-service",
                      service_mappings={"checkout-service": "services/checkout/"},
                      stack=stack, error_signature="AttributeError")
    assert res["strategy"] == "exact_file_line"
    assert res["hits"][0]["file"] == "services/checkout/payment_processor.py"


def test_code_finding_and_fix_generation():
    from agents.code_investigation_agent.agent import CodeInvestigationAgent
    from agents.patch_agent.agent import PatchAgent
    inv = CodeInvestigationAgent().investigate(
        "INC-T", "null_pointer",
        stack_text='File "services/checkout/payment_processor.py", line 24, in process_payment\nAttributeError: x',
        service="checkout-service",
        service_mappings={"checkout-service": "services/checkout/"})
    assert inv.findings and inv.findings[0].file == "services/checkout/payment_processor.py"
    prop = PatchAgent().generate("INC-T", "null_pointer")
    assert prop is not None and "PaymentProfileNotFound" in prop.patch


def test_repo_unavailable_and_no_match_honest():
    from agents.code_investigation_agent.agent import CodeInvestigationAgent
    inv = CodeInvestigationAgent().investigate("INC-T", "unknown", repo_available=False)
    assert "No repository is connected" in (inv.no_fix_reason or "")
    inv2 = CodeInvestigationAgent().investigate(
        "INC-T", "unknown", stack_text="totally unrelated gibberish xyz",
        service="checkout-service",
        service_mappings={"checkout-service": "services/checkout/"})
    assert not inv2.findings and inv2.no_fix_reason


def test_simulation_ground_truth_complete():
    from tools.simulations import TIER1
    required = {"scenario_id", "category", "service", "root_cause", "file",
                "function", "error_signature", "fix_type"}
    assert len(TIER1) >= 15
    for sid, spec in TIER1.items():
        assert required.issubset(spec.keys()), sid
    assert TIER1["null-pointer"]["file"] == "services/checkout/payment_processor.py"
    # demo repo actually contains the fault
    p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "cloud-rca-demo-app", TIER1["null-pointer"]["file"])
    assert os.path.exists(p)
    assert "payment_profile.amount" in open(p, encoding="utf-8").read()


def test_analyze_only_creates_no_incident_and_converts():
    # upload a small log, analyze_only must not create an incident
    content = b"2026-09-10T10:00:00Z ERROR checkout-service AttributeError boom status=500\n"
    up = client.post("/api/logs/upload", data={"project_id": PID},
                     files=[("files", ("t.log", io.BytesIO(content), "text/plain"))])
    assert up.status_code == 200, up.text
    aid = up.json()["analysis_id"]
    before = {c["incident_id"] for c in client.get("/api/incidents/meta").json()}
    r = client.post(f"/api/logs/{aid}/analyze?mode=analyze_only")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["incident_created"] is False and body["session_id"]
    after = {c["incident_id"] for c in client.get("/api/incidents/meta").json()}
    assert before == after
    conv = client.post(f"/api/analysis-sessions/{body['session_id']}/convert",
                       json={"action": "create", "title": "Converted from test"})
    assert conv.status_code == 200 and conv.json()["incident_id"]


def test_e2e_real_incident_flow():
    # onboarded project -> manual incident -> attach log -> RCA identifies file
    r = client.post(f"/api/projects/{PID}/incidents", json={"title": "E2E real checkout 500"})
    iid = r.json()["incident_id"]
    att = client.post(f"/api/incidents/{iid}/attachments",
                      files=[("files", ("checkout-errors.log",
                                        io.BytesIO(b"AttributeError: 'NoneType' status=500\n"),
                                        "text/plain"))])
    assert att.status_code == 200, att.text
    summ = client.get(f"/api/incidents/{iid}/evidence-summary").json()
    assert summ["source"] == "MANUAL"
    assert summ["completeness"]["percent"] > 0
    # code investigation with the null-pointer stack resolves the real file
    from agents.code_investigation_agent.agent import CodeInvestigationAgent
    inv = CodeInvestigationAgent().investigate(
        iid, "null_pointer",
        stack_text='File "services/checkout/payment_processor.py", line 24, in process_payment\nAttributeError: x',
        service="checkout-service",
        service_mappings={"checkout-service": "services/checkout/"})
    assert inv.findings[0].file == "services/checkout/payment_processor.py"


def test_e2e_simulation_flow():
    sim = client.post("/api/simulations/run",
                      json={"scenario": "null-pointer", "service": "checkout-service",
                            "environment": "demo"}).json()
    iid = sim["incident_id"]
    assert sim["ground_truth"]["file"] == "services/checkout/payment_processor.py"
    det = client.get(f"/api/incidents/{iid}").json()
    assert det["is_simulation"] is True
    regen = client.post(f"/api/simulations/{iid}/regenerate")
    assert regen.status_code == 200
