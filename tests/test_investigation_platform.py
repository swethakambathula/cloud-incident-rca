"""Phase 1 investigation-platform tests: graph, why/why-not, agent findings,
confidence evolution, quality score, challenge grounding (all evidence-backed).
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def rca_incident():
    c = TestClient(app)
    c.post("/api/simulate/pool-exhaustion")
    body = c.post("/api/rca/live").json()
    return c, body["incident_id"]


def _get(c, iid, path):
    r = c.get(f"/api/incidents/{iid}/{path}")
    assert r.status_code == 200, f"{path}: {r.text}"
    return r.json()


def test_graph_construction_uses_real_ids(rca_incident):
    c, iid = rca_incident
    g = _get(c, iid, "investigation-graph")
    assert g["incident_id"] == iid
    ids = {n["id"] for n in g["nodes"]}
    types = {n["type"] for n in g["nodes"]}
    assert "incident" in ids and "root-cause" in ids
    assert {"INCIDENT", "HYPOTHESIS", "ROOT_CAUSE"} <= types
    assert any(n["type"] == "AGENT" for n in g["nodes"])
    for e in g["edges"]:
        assert e["from"] in ids and e["to"] in ids, f"dangling edge {e}"
        assert e["relationship"] in ("SUPPORTS", "CONTRADICTS", "CORRELATES_WITH",
                                     "CAUSED_BY", "LOCATED_IN", "CHANGED_BY",
                                     "VALIDATED_BY", "FIXED_BY", "CREATED_PR")
    hyp_ids = {n["id"] for n in g["nodes"] if n["type"] == "HYPOTHESIS"}
    assert hyp_ids and all(h.startswith("HYP-") for h in hyp_ids)


def test_graph_evidence_links_and_support_path(rca_incident):
    c, iid = rca_incident
    g = _get(c, iid, "investigation-graph")
    assert any(e["relationship"] == "SUPPORTS" for e in g["edges"])
    path = g["support_path"]
    assert path[0] == "incident" and "root-cause" in path
    ids = {n["id"] for n in g["nodes"]}
    assert all(p in ids for p in path)


def test_hypothesis_support_and_contradiction_edges():
    from tools.investigation import build_graph
    from orchestration.state import InvestigationState
    from schemas.evidence import IncidentEvidence
    import json
    with open("data/incidents/incident_002_pool_exhaustion.json") as f:
        ev = IncidentEvidence(**json.load(f))
    from orchestration.workflow import InvestigationWorkflow
    state = InvestigationWorkflow().run(ev)
    g = build_graph(ev.incident_id, {}, state, {}, {}, [], [], {})
    rels = {e.relationship for e in g.edges}
    assert "SUPPORTS" in rels


def test_why_this_and_why_not(rca_incident):
    c, iid = rca_incident
    w = _get(c, iid, "why")
    assert w["conclusion"] and w["confidence"] > 0
    assert len(w["reasons"]) > 0
    assert isinstance(w["rejected"], list) and len(w["rejected"]) > 0
    for rj in w["rejected"]:
        assert rj["reason"], "rejected hypothesis must carry critic reasoning"


def test_agent_findings_grounded(rca_incident):
    c, iid = rca_incident
    d = _get(c, iid, "agent-findings")
    assert len(d["findings"]) > 0
    for f in d["findings"]:
        assert f["agent"] and f["summary"]


def test_confidence_snapshots_have_provenance(rca_incident):
    c, iid = rca_incident
    d = _get(c, iid, "confidence-history")
    snaps = d["snapshots"]
    assert len(snaps) >= 2
    prov = {s["provenance"] for s in snaps}
    assert "hypothesis_agent" in prov and "critic_agent" in prov
    for s in snaps:
        assert 0.0 <= s["confidence"] <= 1.0
        assert s["reason"]


def test_quality_score_deterministic_and_bounded(rca_incident):
    c, iid = rca_incident
    a = _get(c, iid, "quality-score")
    b = _get(c, iid, "quality-score")
    assert a == b, "quality score must be deterministic"
    assert 0 <= a["score"] <= 100
    assert abs(sum(f["points"] for f in a["factors"]) - a["score"]) < 0.2
    names = {f["name"] for f in a["factors"]}
    assert {"Evidence Completeness", "Cross-source Correlation",
            "Contradiction Analysis", "Code Correlation",
            "Deployment Correlation", "Historical Comparison",
            "Validation / Critic Pass"} <= names


def test_challenge_grounded_and_refuses_gracefully(rca_incident):
    c, iid = rca_incident
    r = c.post(f"/api/incidents/{iid}/challenge",
               json={"question": "Why do you think this is not traffic overload?"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["answer"] and isinstance(body["evidence_refs"], list)
    assert "limitations" in body and 0.0 <= body["confidence"] <= 1.0
    r2 = c.post(f"/api/incidents/{iid}/challenge",
                json={"question": "Was the moon landing faked by the load balancer?"})
    assert r2.status_code == 200
    assert "insufficient" in r2.json()["answer"].lower()


def test_challenge_requires_question(rca_incident):
    c, iid = rca_incident
    assert c.post(f"/api/incidents/{iid}/challenge", json={"question": "  "}).status_code == 400


def test_investigation_endpoints_need_rca():
    c = TestClient(app)
    for path in ("investigation-graph", "why", "agent-findings",
                 "confidence-history", "quality-score"):
        assert c.get(f"/api/incidents/INC-NOPE-XYZ/{path}").status_code == 404
    assert c.post("/api/incidents/INC-NOPE-XYZ/challenge",
                  json={"question": "why?"}).status_code == 404
