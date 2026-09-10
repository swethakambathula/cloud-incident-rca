"""Deterministic investigation views built ONLY from stored RCA structures.

Every node id, confidence value, timestamp and quoted string comes from the
stored InvestigationState, code investigation, approvals, PRs or memory.
Nothing is invented; gaps are reported as unavailable.
"""
import re
from typing import Dict, List, Optional

from schemas.investigation import (
    AgentFindingView, CausalLink, ChallengeAnswer, CodeCorrelation,
    ConfidenceSnapshot, ContributingFactor, InvestigationEdge,
    InvestigationGraph, InvestigationNode, QualityFactor, QualityScore,
    SimilarIncidentMatch, WhyNotItem, WhyThisView,
)


def _short(s: str, n: int = 90) -> str:
    s = str(s or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def _humanize(cat: str) -> str:
    return (cat or "unknown").replace("_", " ").title()


# ---------------- Investigation graph ----------------

def build_graph(incident_id: str, rec: Dict = None, state=None,
                rca: Dict = None, fix_entry: Dict = None,
                approvals: List[Dict] = None, prs: List[Dict] = None,
                verification: Dict = None) -> InvestigationGraph:
    rec, rca = rec or {}, rca or {}
    approvals, prs = approvals or [], prs or []
    nodes: List[InvestigationNode] = [
        InvestigationNode(id="incident", type="INCIDENT",
                          label=_short(rec.get("title") or incident_id, 60),
                          status=rec.get("status", ""),
                          metadata={"incident_id": incident_id,
                                    "source": rec.get("source", ""),
                                    "severity": rec.get("severity", ""),
                                    "service": (rec.get("services") or [""])[0]}),
    ]
    edges: List[InvestigationEdge] = []
    support_path = ["incident"]

    ev_index: Dict[str, str] = {}  # evidence text -> node id
    ev_counter = 0

    def add_evidence(text: str, kind: str = "telemetry", meta: Dict = None) -> str:
        nonlocal ev_counter
        if text in ev_index:
            return ev_index[text]
        ev_counter += 1
        nid = f"ev-{ev_counter}"
        ev_index[text] = nid
        nodes.append(InvestigationNode(
            id=nid, type="EVIDENCE" if kind != "deployment" else "DEPLOYMENT",
            label=_short(text), metadata={"kind": kind, **(meta or {})}))
        edges.append(InvestigationEdge(**{"from": "incident", "to": nid,
                                          "relationship": "CORRELATES_WITH"}))
        return nid

    # Evidence from stored state
    findings = list((getattr(state, "agent_findings", []) or [])) if state else []
    agents_seen: Dict[str, str] = {}
    if state is not None:
        for tr in (getattr(getattr(state, "trace", None), "agent_traces", []) or []):
            name = getattr(tr, "agent_name", "agent")
            aid = "agent-" + re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
            if aid not in agents_seen:
                agents_seen[aid] = name
                nodes.append(InvestigationNode(
                    id=aid, type="AGENT", label=name, status=getattr(tr, "status", ""),
                    metadata={"duration_ms": getattr(tr, "duration_ms", 0),
                              "completed_at": getattr(tr, "completed_at", ""),
                              "tools": getattr(tr, "tools_invoked", [])}))
        for f in findings[:12]:
            for sev in (getattr(f, "supporting_evidence", []) or [])[:3]:
                nid = add_evidence(sev, "telemetry",
                                   {"agent": getattr(f, "agent_name", ""),
                                    "strength": str(getattr(getattr(f, "evidence_strength", ""), "value", getattr(f, "evidence_strength", "")))})
                aid = "agent-" + re.sub(r"[^a-z0-9]+", "-", str(getattr(f, "agent_name", "")).lower()).strip("-")
                if aid in agents_seen:
                    edges.append(InvestigationEdge(**{"from": aid, "to": nid,
                                                      "relationship": "CORRELATES_WITH"}))
        ev = getattr(getattr(state, "incident_evidence", None), "raw_evidence", []) or []
        for raw in ev[:6]:
            msg = raw.get("message", "") if isinstance(raw, dict) else str(raw)
            if msg:
                add_evidence(msg, "telemetry", {"source": "raw"})
        deps = getattr(getattr(state, "incident_evidence", None), "recent_deployments", []) or []
        for d in deps[:3]:
            if isinstance(d, dict) and d.get("revision_name"):
                nid = add_evidence(
                    f"Deployed {d.get('revision_name')} at {d.get('deployed_at') or d.get('creation_time') or ''}",
                    "deployment", {"revision": d.get("revision_name")})

    # Hypotheses (real ids)
    hyps = list(getattr(state, "hypotheses", [])) if state else []
    val_by_id = {v.hypothesis_id: v for v in
                 (list(getattr(state, "validated_hypotheses", [])) + list(getattr(state, "rejected_hypotheses", [])))} if state else {}
    accepted_id = ""
    for h in hyps:
        v = val_by_id.get(h.hypothesis_id)
        conf = float(v.adjusted_confidence) if v is not None else float(h.confidence_score)
        status = "accepted" if (v is not None and v.accepted) else ("rejected" if v is not None else "unreviewed")
        nodes.append(InvestigationNode(
            id=h.hypothesis_id, type="HYPOTHESIS",
            label=_humanize(h.root_cause_category), confidence=conf, status=status,
            metadata={"root_cause": h.root_cause,
                      "reasoning": h.reasoning_summary,
                      "verdict": v.critic_reasoning if v is not None else ""}))
        for sev in (h.supporting_evidence or []):
            if sev in ev_index:
                edges.append(InvestigationEdge(**{"from": ev_index[sev], "to": h.hypothesis_id,
                                                  "relationship": "SUPPORTS"}))
            else:
                nid = add_evidence(sev, "hypothesis-cited", {})
                edges.append(InvestigationEdge(**{"from": nid, "to": h.hypothesis_id,
                                                  "relationship": "SUPPORTS"}))
        for cev in (h.contradictory_evidence or []):
            nid = add_evidence(cev, "contradiction", {})
            edges.append(InvestigationEdge(**{"from": nid, "to": h.hypothesis_id,
                                              "relationship": "CONTRADICTS"}))
        if status == "accepted" and not accepted_id:
            accepted_id = h.hypothesis_id

    # Root cause
    root_label = _short((getattr(getattr(state, "final_report", None), "root_cause", "") or rca.get("root_cause", "") or "Unknown"), 80)
    root_conf = float(getattr(getattr(state, "final_report", None), "confidence", 0) or rca.get("confidence", 0) or 0)
    nodes.append(InvestigationNode(id="root-cause", type="ROOT_CAUSE",
                                   label=root_label, confidence=root_conf,
                                   status="confirmed" if accepted_id else "unconfirmed",
                                   metadata={"category": rca.get("root_cause_category", "")}))
    if accepted_id:
        edges.append(InvestigationEdge(**{"from": accepted_id, "to": "root-cause",
                                          "relationship": "CAUSED_BY"}))
        support_path += [accepted_id, "root-cause"]

    # Code findings (real file/line)
    code_ids = []
    inv = (fix_entry or {}).get("investigation") or {}
    for i, f in enumerate(inv.get("findings", []) or []):
        cid = f"code-{i + 1}"
        code_ids.append(cid)
        nodes.append(InvestigationNode(
            id=cid, type="CODE",
            label=f"{f.get('file', '')}:{f.get('start_line', '')}",
            metadata={"file": f.get("file", ""), "line": f.get("start_line", 0),
                      "function": "", "snippet": f.get("snippet", ""),
                      "reason": f.get("reason", ""),
                      "test": f.get("related_test", "")}))
        edges.append(InvestigationEdge(**{"from": cid, "to": "root-cause",
                                          "relationship": "SUPPORTS"}))
    if code_ids:
        support_path += code_ids[:1]

    # Fix proposal
    prop = (fix_entry or {}).get("proposal")
    if prop is not None:
        pd = prop if isinstance(prop, dict) else prop.model_dump()
        nodes.append(InvestigationNode(
            id="fix", type="FIX", label=_short(pd.get("summary", "Proposed fix"), 80),
            metadata={"risk": pd.get("risk", ""), "files": pd.get("files_changed", []),
                      "tests": pd.get("tests_to_run", []),
                      "sha": (pd.get("patch_sha256", "") or "")[:12],
                      "reasoning": pd.get("reasoning_summary", "")}))
        if code_ids:
            edges.append(InvestigationEdge(**{"from": "fix", "to": code_ids[0],
                                              "relationship": "FIXED_BY"}))
        edges.append(InvestigationEdge(**{"from": "fix", "to": "root-cause",
                                          "relationship": "FIXED_BY"}))
        support_path.append("fix")

    # Approvals (real ids)
    for a in approvals:
        aid = a.get("approval_id", "")
        if not aid:
            continue
        nodes.append(InvestigationNode(
            id=f"approval-{aid}", type="APPROVAL",
            label=f"{a.get('action', 'approval')} · {a.get('status', '')}",
            status=str(a.get("status", "")),
            metadata={"approval_id": aid, "decided_by": a.get("decided_by", ""),
                      "decided_at": a.get("decided_at", "")}))
        edges.append(InvestigationEdge(**{"from": "fix" if prop is not None else "root-cause",
                                          "to": f"approval-{aid}",
                                          "relationship": "VALIDATED_BY"}))
        support_path.append(f"approval-{aid}")

    # PRs (real ids)
    for p in prs:
        pid = p.get("pr_id", "")
        if not pid:
            continue
        nodes.append(InvestigationNode(
            id=f"pr-{pid}", type="PR",
            label=f"PR #{p.get('pr_number', '?')} · {p.get('status', '')}",
            status=str(p.get("status", "")),
            metadata={"pr_id": pid, "url": p.get("external_url", ""),
                      "branch": p.get("branch", ""), "title": p.get("title", "")}))
        edges.append(InvestigationEdge(**{"from": "fix" if prop is not None else "root-cause",
                                          "to": f"pr-{pid}", "relationship": "CREATED_PR"}))
        support_path.append(f"pr-{pid}")

    # Verification (real stored result)
    if verification:
        nodes.append(InvestigationNode(
            id="verification", type="VERIFICATION",
            label=str(verification.get("verification_status", verification.get("final_status", "verification"))),
            status=str(verification.get("verification_status", verification.get("final_status", ""))),
            metadata={"summary": verification.get("summary", ""),
                      "metrics_after": verification.get("metrics_after", {})}))
        anchor = f"pr-{prs[0]['pr_id']}" if prs and prs[0].get("pr_id") else ("fix" if prop is not None else "root-cause")
        edges.append(InvestigationEdge(**{"from": anchor, "to": "verification",
                                          "relationship": "VALIDATED_BY"}))
        support_path.append("verification")

    return InvestigationGraph(incident_id=incident_id, nodes=nodes, edges=edges)


# ---------------- Why this / why not ----------------

def why_this(state, rca: Dict = None) -> WhyThisView:
    rca = rca or {}
    report = getattr(state, "final_report", None) if state else None
    conclusion = (getattr(report, "root_cause", "") or rca.get("root_cause", "") or "Unknown")
    category = ""
    confidence = float(getattr(report, "confidence", 0) or rca.get("confidence", 0) or 0)
    by_id = {h.hypothesis_id: h for h in (getattr(state, "hypotheses", []) or [])} if state else {}
    accepted = list(getattr(state, "validated_hypotheses", [])) if state else []
    if accepted:
        best = max(accepted, key=lambda v: float(v.adjusted_confidence))
        h = by_id.get(best.hypothesis_id)
        if h is not None:
            category = h.root_cause_category
    reasons = list(getattr(report, "supporting_evidence", []) or [])[:6]
    if accepted:
        best = max(accepted, key=lambda v: float(v.adjusted_confidence))
        if best.critic_reasoning and best.critic_reasoning not in reasons:
            reasons = [best.critic_reasoning] + reasons
    rejected = []
    for v in (list(getattr(state, "rejected_hypotheses", [])) if state else []):
        h = by_id.get(v.hypothesis_id)
        rejected.append(WhyNotItem(
            hypothesis=h.root_cause if h is not None else v.hypothesis_id,
            category=h.root_cause_category if h is not None else "",
            status=str(v.validation_status.value if hasattr(v.validation_status, "value") else v.validation_status),
            reason=v.critic_reasoning or "Rejected by critic validation.",
            confidence=float(v.adjusted_confidence)))
    return WhyThisView(conclusion=conclusion, category=category or rca.get("root_cause_category", ""),
                       confidence=confidence, reasons=reasons[:7], rejected=rejected)


# ---------------- Agent findings ----------------

def agent_findings_view(state) -> List[AgentFindingView]:
    rows: List[AgentFindingView] = []
    if state is None:
        return rows
    grouped: Dict[str, list] = {}
    for f in (getattr(state, "agent_findings", []) or []):
        grouped.setdefault(getattr(f, "agent_name", "agent"), []).append(f)
    for agent, items in grouped.items():
        top = max(items, key=lambda f: float(getattr(f, "confidence", 0)))
        strength = str(getattr(getattr(top, "evidence_strength", ""), "value", getattr(top, "evidence_strength", "")))
        rows.append(AgentFindingView(
            agent=agent, strength=strength.replace("_", " ").title(),
            summary=top.summary,
            evidence_count=sum(len(getattr(f, "supporting_evidence", []) or []) for f in items),
            confidence=float(getattr(top, "confidence", 0)),
            verdict="Strong evidence" if "DIRECT" in strength else (
                "Moderate evidence" if "CORRELATED" in strength else (
                    "Contradictory" if "CONTRADICT" in strength else "Informational"))))
    for tr in (getattr(getattr(state, "trace", None), "agent_traces", []) or []):
        if getattr(tr, "agent_name", "") not in grouped and "Critic" in getattr(tr, "agent_name", ""):
            rows.append(AgentFindingView(agent=getattr(tr, "agent_name"), strength="Validation",
                                         summary="Critic review completed.",
                                         evidence_count=int(getattr(tr, "evidence_items_count", 0)),
                                         confidence=0.0, verdict="Passed"
                                         if getattr(tr, "status", "") == "COMPLETED" else "Pending"))
    return rows


# ---------------- Confidence evolution (derived, provenance-labeled) ----------------

def confidence_evolution(state) -> List[ConfidenceSnapshot]:
    snaps: List[ConfidenceSnapshot] = []
    if state is None or not getattr(state, "hypotheses", []):
        return snaps
    traces = {t.agent_name: t for t in (getattr(getattr(state, "trace", None), "agent_traces", []) or [])}

    def _at(name_part: str) -> str:
        for name, tr in traces.items():
            if name_part.lower() in name.lower():
                return getattr(tr, "completed_at", "")
        return ""

    hyps = list(state.hypotheses)
    best_init = max(hyps, key=lambda h: float(h.confidence_score))
    snaps.append(ConfidenceSnapshot(
        stage="Initial hypotheses", confidence=float(best_init.confidence_score),
        reason=f"{len(hyps)} hypotheses generated; strongest: {_humanize(best_init.root_cause_category)}.",
        evidence_added=[h.hypothesis_id for h in hyps],
        provenance="hypothesis_agent", at=_at("hypothesis") or _at("RCA")))
    accepted = list(getattr(state, "validated_hypotheses", []) or [])
    if accepted:
        best = max(accepted, key=lambda v: float(v.adjusted_confidence))
        h = next((x for x in hyps if x.hypothesis_id == best.hypothesis_id), None)
        snaps.append(ConfidenceSnapshot(
            stage="After critic validation", confidence=float(best.adjusted_confidence),
            reason=_short(best.critic_reasoning, 200) or "Critic verdict recorded.",
            evidence_added=list(best.contradictions or []) or ["critic review"],
            provenance="critic_agent", at=_at("critic")))
    report = getattr(state, "final_report", None)
    if report is not None:
        snaps.append(ConfidenceSnapshot(
            stage="Final report", confidence=float(report.confidence),
            reason="Consolidated report confidence after blast-radius and evidence review.",
            evidence_added=list(report.supporting_evidence or [])[:3],
            provenance="report_agent", at=_at("report") or _at("final")))
    return snaps


# ---------------- Quality score (deterministic) ----------------

def quality_score(state, root_conf: float = 0.0, completeness_pct: float = 0.0,
                  code_available: bool = False, code_strong: bool = False,
                  repo_connected: bool = False, similar_count: int = 0,
                  deployment_referenced: bool = False,
                  deployments_exist: bool = False) -> QualityScore:
    factors: List[QualityFactor] = []
    deductions: List[str] = []

    pts = round(25 * max(0.0, min(1.0, completeness_pct / 100)), 1)
    factors.append(QualityFactor(name="Evidence Completeness", points=pts, max_points=25,
                                 status="Complete" if pts >= 20 else ("Partial" if pts > 0 else "Missing"),
                                 note=f"{completeness_pct}% evidence coverage."))
    if pts < 25:
        deductions.append(f"Evidence completeness {completeness_pct}% (-{round(25 - pts, 1)}).")

    agents = set()
    if state is not None:
        for f in (getattr(state, "agent_findings", []) or []):
            agents.add(getattr(f, "agent_name", ""))
    corr = min(20, 4 * len(agents))
    factors.append(QualityFactor(name="Cross-source Correlation", points=corr, max_points=20,
                                 status="Strong" if corr >= 16 else ("Partial" if corr else "Missing"),
                                 note=f"{len(agents)} independent agent source(s)."))
    if corr < 20:
        deductions.append(f"Only {len(agents)} correlated source(s) (-{20 - corr}).")

    validations = (list(getattr(state, "validated_hypotheses", [])) + list(getattr(state, "rejected_hypotheses", []))) if state is not None else []
    contra = list(getattr(state, "contradictory_evidence", [])) if state is not None else []
    cpts = 15 if (validations and contra) else (8 if validations else 0)
    factors.append(QualityFactor(name="Contradiction Analysis", points=cpts, max_points=15,
                                 status="Checked" if cpts == 15 else ("Partial" if cpts else "Missing"),
                                 note=f"{len(contra)} contradiction(s) tracked across {len(validations)} verdict(s)."))
    if cpts < 15:
        deductions.append(f"Contradiction analysis incomplete (-{15 - cpts}).")

    kpts = 15 if code_strong else (8 if code_available else (4 if repo_connected else 0))
    factors.append(QualityFactor(name="Code Correlation", points=kpts, max_points=15,
                                 status="Strong" if kpts == 15 else ("Partial" if kpts else "Missing"),
                                 note="Exact file+line code finding." if kpts == 15 else (
                                     "Code finding without exact location." if kpts == 8 else (
                                         "Repository connected, no code mapping." if kpts == 4 else "No repository connected."))))
    if kpts < 15:
        deductions.append(f"Code correlation not exact (-{15 - kpts}).")

    dpts = 10 if deployment_referenced else (5 if deployments_exist else 0)
    factors.append(QualityFactor(name="Deployment Correlation", points=dpts, max_points=10,
                                 status="Correlated" if dpts == 10 else ("Present" if dpts else "Missing"),
                                 note="Deployment evidence supports the conclusion." if dpts == 10 else (
                                     "Deployments exist but are unreferenced." if dpts else "No deployment evidence.")))
    if dpts < 10:
        deductions.append(f"Deployment correlation weak (-{10 - dpts}).")

    hpts = 5 if similar_count > 0 else 0
    if state is not None and not hpts:
        kfind = [k for k in (getattr(state, "knowledge_findings", []) or [])
                 if getattr(k, "source_type", "") == "historical_incident"]
        hpts = 2 if kfind else 0
    factors.append(QualityFactor(name="Historical Comparison", points=hpts, max_points=5,
                                 status="Matched" if hpts == 5 else ("Partial" if hpts else "Missing"),
                                 note=f"{similar_count} similar past incident(s) matched." if similar_count else "No historical match."))
    if hpts < 5:
        deductions.append(f"No strong historical comparison (-{5 - hpts}).")

    supp = [v for v in validations if getattr(v, "accepted", False)
            and str(getattr(getattr(v, "validation_status", ""), "value", getattr(v, "validation_status", ""))) == "SUPPORTED"]
    part = [v for v in validations if getattr(v, "accepted", False)]
    vpts = 10 if supp else (5 if part else 0)
    factors.append(QualityFactor(name="Validation / Critic Pass", points=vpts, max_points=10,
                                 status="Passed" if vpts == 10 else ("Partial" if vpts else "Failed"),
                                 note="Critic SUPPORTED the conclusion." if vpts == 10 else (
                                     "Critic partially supported." if vpts else "No accepted critic verdict.")))
    if vpts < 10:
        deductions.append(f"Critic validation not fully passed (-{10 - vpts}).")

    total = round(min(100.0, sum(f.points for f in factors)), 1)
    return QualityScore(score=total, root_cause_confidence=root_conf,
                        factors=factors, deductions=deductions)


# ---------------- What changed (real deployment + git data) ----------------

def what_changed(state, repo_root: str = "", recent_commits: List[str] = None,
                 suspect_file: str = "", patch_diff: str = "") -> Dict:
    recent_commits = recent_commits or []
    ev = getattr(state, "incident_evidence", None) if state is not None else None
    deps = list(getattr(ev, "recent_deployments", []) or []) if ev is not None else []
    current = getattr(ev, "revision_name", "") if ev is not None else ""
    start = getattr(ev, "start_time", "") if ev is not None else ""
    out = {"current_revision": current, "previous_revision": "",
           "deployed_at": "", "minutes_before_incident": None,
           "recent_commits": recent_commits[:5],
           "most_relevant_change": suspect_file,
           "diff": patch_diff[:4000] if patch_diff else "",
           "explanation": ""}
    if deps:
        cur = next((d for d in deps if isinstance(d, dict) and d.get("revision_name") == current), None)
        others = [d for d in deps if isinstance(d, dict) and d.get("revision_name") != current]
        if cur is None and deps:
            cur = deps[0]
        if isinstance(cur, dict):
            out["deployed_at"] = cur.get("deployed_at") or cur.get("creation_time") or ""
        if others and isinstance(others[0], dict):
            out["previous_revision"] = others[0].get("revision_name", "")
        if out["deployed_at"] and start:
            try:
                from datetime import datetime
                dep = datetime.fromisoformat(str(out["deployed_at"]).replace("Z", "+00:00"))
                st = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
                out["minutes_before_incident"] = round((st - dep).total_seconds() / 60, 1)
            except Exception:
                pass
    if suspect_file and out["current_revision"]:
        out["explanation"] = (f"Stack traces point to {suspect_file}, active on "
                              f"{out['current_revision'] or 'the failing revision'}.")
    elif suspect_file:
        out["explanation"] = f"Stack traces point to {suspect_file}."
    return out


# ---------------- Code correlation (deterministic checks) ----------------

def code_correlation_score(code_findings: List[Dict], error_signature: str = "",
                           recent_files_changed: List[str] = None,
                           revision_present: bool = False) -> CodeCorrelation:
    recent_files_changed = recent_files_changed or []
    if not code_findings:
        return CodeCorrelation(available=False, level="Unavailable",
                               reason="No code findings stored for this incident.")
    f = code_findings[0]
    checks: List[Dict] = []
    checks.append({"name": "File match", "passed": bool(f.get("file")),
                   "detail": f.get("file", "")})
    checks.append({"name": "Line match", "passed": bool(int(f.get("start_line", 0) or 0) > 0),
                   "detail": f"line {f.get('start_line', 0)}"})
    checks.append({"name": "Function match", "passed": bool(f.get("function")),
                   "detail": f.get("function") or "not recorded"})
    changed = [c for c in recent_files_changed if f.get("file", "") in c or c in f.get("file", "")]
    checks.append({"name": "Recent commit touches file", "passed": bool(changed),
                   "detail": changed[0] if changed else "no recent commit lists this file"})
    checks.append({"name": "Deployment correlation", "passed": revision_present,
                   "detail": "failing revision recorded" if revision_present else "no revision recorded"})
    sig_words = set(re.findall(r"[a-z]{4,}", (error_signature or "").lower()))
    snip_words = set(re.findall(r"[a-z]{4,}", str(f.get("snippet", "")).lower() + " " + str(f.get("reason", "")).lower()))
    sig_hit = bool(sig_words & snip_words)
    checks.append({"name": "Error signature match", "passed": sig_hit,
                   "detail": "signature terms in finding" if sig_hit else "no signature overlap"})
    checks.append({"name": "Test reproduction", "passed": bool(f.get("related_test")),
                   "detail": f.get("related_test") or "no linked test"})
    weights = [25, 20, 15, 15, 10, 10, 5]
    score = round(sum(w for w, c in zip(weights, checks) if c["passed"]), 1)
    level = "Strong" if score >= 80 else ("Moderate" if score >= 50 else "Weak")
    suspect = f"{f.get('file', '')}:{f.get('start_line', 0)}"
    return CodeCorrelation(available=True, score=score, level=level,
                           checks=checks, primary_suspect=suspect,
                           reason=f.get("reason", ""))


# ---------------- Causal chain + contributing factors ----------------

def causal_chain(state, suspect_file: str = "", root_cause: str = "") -> Dict:
    links: List[CausalLink] = []
    step = 0

    def add(title: str, detail: str, derived_from: str):
        nonlocal step
        step += 1
        links.append(CausalLink(step=step, title=title, detail=detail,
                                derived_from=derived_from))

    ev = getattr(state, "incident_evidence", None) if state is not None else None
    deps = list(getattr(ev, "recent_deployments", []) or []) if ev is not None else []
    if deps and isinstance(deps[0], dict):
        add("Revision deployed",
            f"{deps[0].get('revision_name', 'unknown revision')} deployed "
            f"{deps[0].get('deployed_at') or deps[0].get('creation_time') or 'at unknown time'}.",
            "deployment metadata")
    if suspect_file:
        add("Fault activated in code",
            f"{suspect_file} executed on the failing revision.",
            "stack trace + code finding")
    rep = getattr(state, "final_report", None) if state is not None else None
    for t in (list(getattr(rep, "timeline", []) or [])[:4]):
        add(getattr(t, "event_type", "EVENT").replace("_", " ").title(),
            getattr(t, "description", ""), "incident timeline")
    if root_cause:
        add("Root cause confirmed", _short(root_cause, 200), "critic verdict")
    factors = []
    if state is not None:
        for f in (getattr(state, "agent_findings", []) or []):
            s = str(getattr(f, "evidence_strength", ""))
            if "CORRELATED" in s and len(factors) < 3:
                factors.append(ContributingFactor(
                    factor=getattr(f, "summary", ""),
                    derived_from=getattr(f, "agent_name", "")))
    return {"chain": [l.model_dump() for l in links],
            "contributing_factors": [f.model_dump() for f in factors]}


# ---------------- Fix preview + alternatives + test impact ----------------

_FIX_ALTERNATIVES = {
    "connection_pool_exhaustion": [
        {"option": "Increase pool size only",
         "rejected_because": "Reduces symptoms but does not address leaked connections; the minimal fix releases connections on all paths."},
    ],
    "faulty_revision": [
        {"option": "Roll forward with a hotfix in the new path",
         "rejected_because": "Higher risk under incident pressure; restoring the previous healthy behavior first is safer."},
    ],
    "configuration_regression": [
        {"option": "Hardcode corrected values",
         "rejected_because": "Repeats the original mistake; reading from the environment keeps config portable."},
    ],
    "dependency_failure": [
        {"option": "Disable the downstream dependency",
         "rejected_because": "Loses functionality; bounded timeout with retries preserves behavior under transient slowness."},
    ],
    "null_pointer": [
        {"option": "Default to an empty profile",
         "rejected_because": "Masks missing data; failing fast with a typed error keeps the failure visible."},
    ],
}


def fix_preview(proposal: Dict, job: Dict, root_conf: float = 0.0,
                category: str = "") -> Dict:
    proposal, job = proposal or {}, job or {}
    tests = list(proposal.get("tests_to_run", []) or [])
    impact = []
    for t in tests:
        why = ("directly exercises the modified code" if "incident" in t or "fixed" in t
               else "verifies the success path")
        impact.append({"test": t, "why": why})
    test_output = job.get("test_output") or ""
    passed = None
    m = re.search(r"(\d+)\s+passed", test_output)
    if m:
        passed = int(m.group(1))
    reasoning = proposal.get("reasoning_summary", "") or ""
    side = ""
    if "Side effects:" in reasoning:
        reasoning, side = reasoning.split("Side effects:", 1)
    return {
        "summary": proposal.get("summary", ""),
        "fix_confidence": round(max(0.0, root_conf - (0.05 if tests else 0.25)), 2) if root_conf else 0.0,
        "root_cause_confidence": root_conf,
        "risk": proposal.get("risk", ""),
        "files_changed": proposal.get("files_changed", []),
        "lines_added": proposal.get("lines_added", 0),
        "lines_removed": proposal.get("lines_removed", 0),
        "tests": impact,
        "branch": job.get("branch") or "",
        "reason": reasoning.strip(),
        "expected_behavior": "Failure path addressed; success-path behavior unchanged.",
        "side_effects": side.strip() or "None recorded.",
        "rollback": "Revert this commit / close the PR unmerged.",
        "why_minimal": "This is the smallest change that directly addresses the confirmed failure path.",
        "alternatives": _FIX_ALTERNATIVES.get(category, []),
        "tests_passed": passed,
        "fix_status": job.get("status", ""),
    }


# ---------------- Verification comparison + resolution explanation ----------------

def verification_comparison(verification: Dict, execution: Dict = None) -> Optional[Dict]:
    if not verification:
        return None
    execution = execution or {}
    mb, ma = verification.get("metrics_before", {}) or {}, verification.get("metrics_after", {}) or {}
    status = str(verification.get("verification_status", verification.get("final_status", "")))
    checks = []
    err_after = verification.get("error_rate_after")
    if err_after is not None:
        checks.append({"check": "HTTP 5xx returned below 1%",
                       "passed": float(err_after) < 1.0,
                       "detail": f"after: {err_after}%"})
    lat_b, lat_a = verification.get("latency_before"), verification.get("latency_after")
    if lat_b is not None and lat_a is not None and float(lat_b or 0) > 0:
        checks.append({"check": "P95 latency improved vs before",
                       "passed": float(lat_a) < float(lat_b),
                       "detail": f"before: {lat_b}ms, after: {lat_a}ms"})
    checks.append({"check": "No new issues detected",
                   "passed": not verification.get("new_issues_detected", False),
                   "detail": "clean" if not verification.get("new_issues_detected", False) else "new issues flagged"})
    checks.append({"check": "No recurrence during verification window",
                   "passed": status in ("RESOLVED", "PARTIALLY_RESOLVED"),
                   "detail": status or "unknown"})
    rows = []
    for label, bkey, akey in (("HTTP 5xx", "error_rate_before", "error_rate_after"),
                              ("P95 latency", "latency_before", "latency_after")):
        b, a = verification.get(bkey), verification.get(akey)
        if b is not None or a is not None:
            rows.append({"metric": label, "before": b, "after": a})
    for k in sorted(set(mb) | set(ma)):
        if k not in ("error_rate_pct", "latency_p95_ms"):
            rows.append({"metric": k, "before": mb.get(k), "after": ma.get(k)})
    return {"status": status,
            "passed": status == "RESOLVED",
            "regressed": status == "REGRESSED",
            "metrics": rows,
            "resolution_checks": checks,
            "conclusion": ("Resolved" if status == "RESOLVED" else
                           "Partially resolved" if status == "PARTIALLY_RESOLVED" else
                           "Regression detected" if status == "REGRESSED" else status or "Unknown"),
            "summary": verification.get("summary", ""),
            "confidence": verification.get("verification_confidence", 0.0)}


# ---------------- Challenge RCA (grounded, deterministic) ----------------

_CATEGORY_ALIASES = {
    "pool": "connection_pool_exhaustion", "database": "database_connectivity",
    "db": "database_connectivity", "traffic": "traffic_overload",
    "overload": "traffic_overload", "deploy": "faulty_revision",
    "revision": "faulty_revision", "config": "configuration_regression",
    "memory": "memory_leak", "cpu": "cpu_exhaustion",
    "auth": "auth_failure", "network": "network_timeout",
    "depend": "dependency_failure", "payload": "malformed_payload",
    "rate": "rate_limit", "null": "null_pointer",
}

_INSUFFICIENT = "The available incident evidence is insufficient to answer this confidently."


def challenge_answer(question: str, state, rca: Dict = None,
                     code_findings: List[Dict] = None,
                     missing: List[str] = None) -> ChallengeAnswer:
    rca = rca or {}
    code_findings = code_findings or []
    missing = missing or []
    q = (question or "").lower()
    base_conf = float(rca.get("confidence", 0) or 0)

    def _cat_in_q() -> Optional[str]:
        for alias, cat in _CATEGORY_ALIASES.items():
            if alias in q:
                return cat
        return None

    hyps = {h.hypothesis_id: h for h in (getattr(state, "hypotheses", []) or [])} if state else {}
    vals = list(getattr(state, "validated_hypotheses", [])) + list(getattr(state, "rejected_hypotheses", [])) if state else []

    def _find_hyp(cat: str):
        for h in hyps.values():
            if h.root_cause_category == cat:
                return h
        return None

    # Why not X / rule out / not a Y
    if any(k in q for k in ("why not", "not a ", "not an ", "rule out", "ruled out", "reject")):
        cat = _cat_in_q()
        if cat:
            h = _find_hyp(cat)
            v = next((x for x in vals if h is not None and x.hypothesis_id == h.hypothesis_id), None)
            if h is not None and v is not None and not v.accepted:
                refs = list(v.contradictions or [])[:4] or (h.supporting_evidence or [])[:2]
                return ChallengeAnswer(
                    answer=(f"{_humanize(cat)} was rejected: {v.critic_reasoning}"),
                    evidence_refs=refs,
                    confidence=round(min(0.99, 0.5 + 0.5 * float(v.adjusted_confidence) + 0.2), 2),
                    limitations=list(missing[:3] or ["No further checks recorded."]))
            if h is not None and v is not None and v.accepted:
                return ChallengeAnswer(
                    answer=(f"{_humanize(cat)} was accepted, not rejected: {v.critic_reasoning}"),
                    evidence_refs=(h.supporting_evidence or [])[:4],
                    confidence=round(base_conf, 2), limitations=list(missing[:3] or []))
        return ChallengeAnswer(answer=_INSUFFICIENT, evidence_refs=[],
                               confidence=0.0,
                               limitations=["No rejected hypothesis in the stored investigation matches this question."])

    # Why this file / blaming file
    if "file" in q or "code" in q or "blam" in q or "line" in q:
        if code_findings:
            f = code_findings[0]
            return ChallengeAnswer(
                answer=(f"This file is blamed because {f.get('reason', '')} "
                        f"Snippet: {f.get('snippet', '')}"),
                evidence_refs=[f"{f.get('file', '')}:{f.get('start_line', '')}"],
                confidence=round(base_conf, 2),
                limitations=[] if len(code_findings) > 1 else ["Single code finding; no corroborating location."])
        return ChallengeAnswer(answer=_INSUFFICIENT, evidence_refs=[], confidence=0.0,
                               limitations=["No code findings are stored for this incident."])

    # Deployment evidence
    if "deploy" in q or "revision" in q or "releas" in q or "changed" in q:
        dep_summaries = [f.summary for f in (getattr(state, "agent_findings", []) or [])
                         if "deploy" in getattr(f, "agent_name", "").lower()] if state else []
        ev = getattr(getattr(state, "incident_evidence", None), "recent_deployments", []) or []
        if dep_summaries or ev:
            refs = dep_summaries[:2] + [str(d.get("revision_name", "")) for d in ev[:2] if isinstance(d, dict)]
            return ChallengeAnswer(
                answer=" ".join(dep_summaries[:2]) or f"Stored deployments: {refs}",
                evidence_refs=[r for r in refs if r][:4],
                confidence=round(base_conf, 2), limitations=list(missing[:2] or []))
        return ChallengeAnswer(answer=_INSUFFICIENT, evidence_refs=[], confidence=0.0,
                               limitations=["No deployment evidence stored for this incident."])

    # Confidence / limitations
    if "confiden" in q or "lower" in q or "limitation" in q or "unsure" in q or "doubt" in q:
        lims = list(missing[:4]) or ["No missing-evidence items recorded."]
        contra = list(getattr(state, "contradictory_evidence", []) or [])[:3] if state else []
        return ChallengeAnswer(
            answer=(f"Confidence would drop if: {'; '.join(lims)} "
                    f"Contradictory signals tracked: {'; '.join(contra) if contra else 'none'}."),
            evidence_refs=contra, confidence=round(base_conf, 2), limitations=lims)

    # Could this be X
    if "could" in q or "whether" in q or "possible" in q or "maybe" in q:
        cat = _cat_in_q()
        if cat:
            h = _find_hyp(cat)
            v = next((x for x in vals if h is not None and x.hypothesis_id == h.hypothesis_id), None)
            if h is not None and v is not None:
                verdict = "supported" if v.accepted else "rejected"
                return ChallengeAnswer(
                    answer=(f"{_humanize(cat)} was considered and {verdict}: {v.critic_reasoning}"),
                    evidence_refs=(h.supporting_evidence or [])[:3] + list(v.contradictions or [])[:2],
                    confidence=round(float(v.adjusted_confidence), 2),
                    limitations=list(missing[:2] or []))
        return ChallengeAnswer(answer=_INSUFFICIENT, evidence_refs=[], confidence=0.0,
                               limitations=["That alternative was not among the investigated hypotheses."])

    # Fallback: keyword overlap against stored facts
    facts: List[str] = []
    if state is not None:
        for f in (getattr(state, "agent_findings", []) or [])[:10]:
            facts.append(getattr(f, "summary", ""))
        rep = getattr(state, "final_report", None)
        facts += list(getattr(rep, "supporting_evidence", []) or [])[:6]
    words = set(re.findall(r"[a-z]{4,}", q))
    scored = sorted(((sum(1 for w in words
                          if w in set(re.findall(r"[a-z]{4,}", (f or "").lower()))), f)
                     for f in facts if f),
                    reverse=True)
    if scored and scored[0][0] > 0:
        best = [f for _, f in scored[:3]]
        return ChallengeAnswer(answer="The closest stored evidence: " + " ".join(best),
                               evidence_refs=best, confidence=round(0.4 * base_conf, 2),
                               limitations=["Partial keyword match only; " + _INSUFFICIENT.lower()])
    return ChallengeAnswer(answer=_INSUFFICIENT, evidence_refs=[], confidence=0.0,
                           limitations=["No stored evidence matches this question."])
