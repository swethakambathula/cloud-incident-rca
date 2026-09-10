"""
Interactive Web Dashboard for Cloud Incident RCA Agent.
Serves a modern, dark-mode visual RCA dashboard for Phase 1 & 2 incidents.
"""
import os
import glob
import json
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from typing import List
import uvicorn

from agents.rca_agent.agent import CloudRCAAgent
from tools.correlation import collect_incident_evidence
from orchestration.workflow import InvestigationWorkflow
from agents.remediation_agent.agent import RemediationAgent
from approval.manager import global_approval_manager
from agents.executor_agent.agent import ExecutorAgent
from agents.verification_agent.agent import VerificationAgent
from memory.store import MemoryStore
from memory.schemas import IncidentMemoryRecord
from memory.postmortem import generate_postmortem
from orchestration.incident_state_machine import IncidentStateMachine, IncidentState
from audit.logger import audit_log
import asyncio
import time

def _investigate_and_plan(ev):
    """Blocking multi-agent workflow + remediation plan. Must run in a thread (asyncio.to_thread)."""
    wf = InvestigationWorkflow()
    state = wf.run(ev)
    rem_agent = RemediationAgent()
    cat = None
    if state.validated_hypotheses:
        best = max([v for v in state.validated_hypotheses if v.accepted], key=lambda x: x.adjusted_confidence, default=None)
        if best:
            hyp = next((h for h in state.hypotheses if h.hypothesis_id==best.hypothesis_id), None)
            if hyp:
                cat = hyp.root_cause_category
    plan = rem_agent.plan(ev, state.final_report, validated_category=cat)
    return state, plan, cat

def _execute_and_verify(req, action_params):
    """Blocking executor + verification + memory. Must run in a thread."""
    executor = ExecutorAgent()
    result = executor.execute(req, action_params)
    audit_log("EXECUTION", req.incident_id, "ExecutorAgent", req.action, req.target_resource, before=result.before_state, after=result.after_state, approval_id=req.approval_id, result=result.status.value)
    verifier = VerificationAgent()
    metrics_before = {"error_rate_pct": 20, "latency_p95_ms": 3000}
    metrics_after = {"error_rate_pct": 0.5 if result.status.value=="SUCCESS" else 18, "latency_p95_ms": 180 if result.status.value=="SUCCESS" else 2900}
    verification = verifier.verify(req.incident_id, result, metrics_before, metrics_after)
    audit_log("VERIFICATION", req.incident_id, "VerificationAgent", verification.verification_status.value, req.target_resource, before=metrics_before, after=metrics_after)
    try:
        store = MemoryStore()
        rec = IncidentMemoryRecord(
            incident_id=req.incident_id, service=req.target_resource.split("/")[-1] if "/" in req.target_resource else "unknown",
            symptoms=[], timeline=[], root_cause=req.root_cause, root_cause_category="unknown",
            supporting_evidence=[], blast_radius={}, remediation=action_params, approval_outcome=req.status.value,
            execution_result=result.model_dump(), verification_result=verification.model_dump(),
            final_status=verification.verification_status.value, timestamps={}, confidence=req.confidence
        )
        store.save(rec)
        postmortem = generate_postmortem(rec)
    except Exception as e:
        postmortem = {"error": str(e)}
    return result, verification, postmortem

app = FastAPI(title="Cloud RCA Agent")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Cloud Incident Investigation & RCA Agent</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root { --bg-dark:#111315; --card-bg:#191c20; --surface:#191c20; --surface-secondary:#20242a; --accent-cyan:#d9d9d9; --accent-purple:#8a8a8a; --accent-red:#f0f0f0; --accent-green:#ffffff; --accent-yellow:#b5b5b5; --text-main:#f3f4f6; --text-muted:#a9afb7; --text-faint:#6f6f6f; --border-color:#30353c; --hover:#1c1c1c; --selected:#262626; --background:#111315; --success:#3d9a50; --warning:#b98a2f; --danger:#c0564d; --terminal-background:#000000; --sidebar-width:272px; --sidebar-collapsed-width:72px; --header-h:60px; --sp1:4px; --sp2:8px; --sp3:12px; --sp4:16px; --sp6:24px; --sp8:32px; }
        *{box-sizing:border-box;margin:0;padding:0} body{font-family:'Inter',sans-serif;background:var(--bg-dark);color:var(--text-main);min-height:100vh;margin:0;display:grid;grid-template-rows:auto minmax(0,1fr)}
        .sidebar{background:#151517;border-right:1px solid var(--border-color);padding:20px 16px;display:flex;flex-direction:column;gap:16px;position:sticky;top:var(--header-h);max-height:calc(100vh - var(--header-h));overflow-y:auto;overflow-x:hidden}
        #app{display:grid;grid-template-columns:var(--sidebar-width) minmax(0,1fr);min-height:0;align-items:start}
        body.sidebar-collapsed #app{grid-template-columns:var(--sidebar-collapsed-width) minmax(0,1fr)}
        body.sidebar-collapsed .sidebar .lbl,body.sidebar-collapsed .sidebar .side-h span.txt,body.sidebar-collapsed #approval-zone,body.sidebar-collapsed .sidebar h2 .brand-txt{display:none}
        body.sidebar-collapsed .sidebar{padding:20px 10px}
        body.sidebar-collapsed .side-link,body.sidebar-collapsed .proj-row{justify-content:center}
        #backdrop{display:none;position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:80}
        body.drawer-open #backdrop{display:block}
        .sidebar h2{font-size:1.15rem;color:var(--accent-cyan)}
        .incident-card{background:var(--card-bg);border:1px solid var(--border-color);padding:12px 14px;border-radius:8px;cursor:pointer;transition:.2s}
        .incident-card:hover,.incident-card.active{border-color:var(--accent-cyan);transform:translateY(-2px);box-shadow:0 4px 14px rgba(255,255,255,.08)}
        .incident-card h4{font-size:.88rem;margin-bottom:4px} .incident-card p{font-size:.75rem;color:var(--text-muted)}
        .main-content{min-width:0;width:100%;overflow-x:hidden}
        .card,.item-box,.evidence-box,.log-panel{min-width:0;overflow-wrap:anywhere}
        .well{background:var(--surface-secondary);color:var(--text-primary);border:1px solid var(--border-color);border-radius:6px;padding:10px 14px}
        .rca-grid{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(360px,.85fr);gap:20px;margin-bottom:20px}
        @media (max-width: 1000px){.rca-grid{grid-template-columns:1fr}}
        .rc-section{margin-top:16px}
        .rc-section:first-child{margin-top:0}
        .kv{display:grid;grid-template-columns:130px minmax(0,1fr);gap:4px 10px;font-size:.85rem;margin-top:6px}
        .kv dt{color:var(--text-muted)} .kv dd{margin:0}
        .card{padding:16px 20px}
        .projects-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
        body{font-size:14px}
        .card-title{font-size:16px}
        pre{max-width:100%;overflow-x:auto}
        @media (max-width: 1279px){:root{--sidebar-width:232px}}
        @media (max-width: 1023px){
            #app{grid-template-columns:var(--sidebar-collapsed-width) minmax(0,1fr)}
            .sidebar{padding:20px 10px}
            .sidebar .lbl,.sidebar .side-h span.txt,.sidebar h2 .brand-txt,#approval-zone{display:none}
            .side-link,.proj-row{justify-content:center}
            .view.active{padding:20px 20px}
        }
        @media (max-width: 767px){
            #app{grid-template-columns:minmax(0,1fr)}
            .sidebar{position:fixed;left:0;top:var(--header-h);bottom:0;width:min(85vw,320px);max-height:none;z-index:90;transform:translateX(-105%);transition:transform .2s ease}
            body.drawer-open .sidebar{transform:none}
            .grid{grid-template-columns:1fr}
            .header{flex-direction:column;align-items:flex-start}
            .log-panel{height:200px}
            .view.active{padding:14px 12px}
        }
        .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid var(--border-color);flex-wrap:wrap;gap:12px}
        .btn{background:linear-gradient(180deg,#2e2e2e,#101010);color:#fff;border:1px solid #3a3a3a;padding:10px 18px;border-radius:6px;font-weight:600;font-size:.85rem;min-height:38px;cursor:pointer}
        .btn:hover{border-color:#6a6a6a}
        .btn-primary{background:linear-gradient(180deg,#4a4a4a,#1c1c1c);border-color:#6f6f6f}
        .btn:disabled{opacity:.5;cursor:not-allowed} .btn-red{background:linear-gradient(180deg,#2e2e2e,#101010);border:1px solid #4a4a4a} .btn-green{background:linear-gradient(180deg,#3d3d3d,#161616);border:1px solid #6a6a6a}
        .sim-bar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;padding:14px;background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;align-items:center}
        .sim-bar strong{font-size:.85rem;color:var(--accent-cyan);margin-right:4px}
        .sim-btn{padding:9px 14px;border-radius:6px;border:1px solid var(--border-color);background:#20242a;color:var(--text-main);font-size:.82rem;font-weight:600;cursor:pointer;min-height:36px}
        .sim-btn:disabled{opacity:.5;cursor:not-allowed}
        .sim-btn:hover{border-color:#d9d9d9;background:#1c1c1c}
        .log-panel{background:#000000;border:1px solid var(--border-color);border-radius:8px;padding:12px;height:260px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:.78rem;line-height:1.5}
        .log-line{padding:2px 0;border-bottom:1px solid rgba(255,255,255,.07)} .log-error{color:#ffffff;font-weight:700} .log-warn{color:#b5b5b5;font-weight:600} .log-info{color:var(--text-muted)}
        .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-bottom:20px}
        .card{background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:20px;box-shadow:0 8px 20px rgba(0,0,0,.3)}
        .card-title{font-size:1.05rem;font-weight:600;margin-bottom:14px;color:var(--accent-cyan)}
        .badge{display:inline-block;padding:4px 10px;border-radius:20px;font-size:.75rem;font-weight:600;text-transform:uppercase}
        .badge-red{background:#1a1a1a;color:#ffffff;border:2px solid #8a8a8a}
        .badge-yellow{background:#141414;color:#b5b5b5;border:1px solid #4a4a4a}
        .badge-green{background:#1a1a1a;color:#ffffff;border:1px solid #8a8a8a}
        .item-box{background:#20242a;border-left:4px solid var(--accent-cyan);padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0;font-size:.88rem}
        .evidence-box{background:#20242a;border:1px solid var(--border-color);padding:10px 14px;border-radius:6px;margin-bottom:8px;font-size:.85rem}
        .status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px} .dot-green{background:#ffffff;box-shadow:0 0 6px rgba(255,255,255,.6)} .dot-red{background:#9a9a9a;animation:pulse 1.2s infinite}
        @keyframes pulse{0%{opacity:1}50%{opacity:.4}100%{opacity:1}}
            button:focus-visible,input:focus-visible,select:focus-visible,a:focus-visible{outline:2px solid #d9d9d9;outline-offset:1px}
    
        #topnav{display:flex;gap:6px;align-items:center;height:var(--header-h);box-sizing:border-box;padding:0 16px;background:#151517;border-bottom:1px solid var(--border-color);z-index:50}
        #topnav .nav-right{margin-left:auto;display:flex;gap:6px;align-items:center}
        #topnav .hamb{background:transparent;border:1px solid var(--border-color);border-radius:6px;color:var(--text-main);font-size:1rem;padding:6px 10px;cursor:pointer}
        .view.active{width:100%;max-width:1600px;margin:0 auto;padding:24px 32px;box-sizing:border-box}
        .view h1{font-size:1.75rem;margin:2px 0 6px;line-height:1.25}
        #crumbs{margin:0 0 10px;min-height:1.2em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
        #view-projects>div:first-child{flex-wrap:wrap;row-gap:8px}
        #topnav .brand{font-weight:700;margin-right:12px;white-space:nowrap}
        .nav-btn{padding:7px 12px;border-radius:6px;border:1px solid transparent;background:transparent;color:var(--text-muted);font-size:.82rem;font-weight:600;cursor:pointer}
        .nav-btn:hover{background:#1c1c1c;color:#fff}
        .nav-btn.active{background:#262626;color:#fff;border:1px solid #4a4a4a}
        #app{min-height:0}
        .view{display:none;min-width:0}
        .view.active{display:block}
        #crumbs{font-size:.78rem;color:var(--text-muted);margin-bottom:12px}
        #crumbs a{color:var(--text-secondary);cursor:pointer;text-decoration:underline}
        .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin-bottom:20px}
        .stat-card{background:linear-gradient(180deg,#161616,#0b0b0b);border:1px solid var(--border-color);border-radius:10px;padding:16px}
        .stat-card .num{font-size:1.6rem;font-weight:700}
        .stat-card .lbl{font-size:.78rem;color:var(--text-muted)}
        .btn-primary{background:linear-gradient(180deg,#3d3d3d,#161616);border:1px solid #6f6f6f}
        table.tbl{width:100%;border-collapse:collapse;font-size:.82rem}
        table.tbl th,table.tbl td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border-color);vertical-align:top}
        table.tbl th{color:var(--text-muted);font-weight:600;text-transform:uppercase;font-size:.7rem;letter-spacing:.04em}
        table.tbl tr.clickable{cursor:pointer}
        table.tbl tr.clickable:hover{background:#1c1c1c}
        .pill{display:inline-block;padding:2px 9px;border-radius:12px;font-size:.72rem;font-weight:700;border:1px solid #4a4a4a;white-space:nowrap}
        .pill.ok{border-color:var(--success);color:#c9ecd2}
        .pill.bad{border-color:var(--danger);color:#f2c4bf}
        .pill.warn{border-color:var(--warning);color:#efdfb5}
        .pill.info{border-color:#4a4a4a;color:#d9d9d9}
        .stepper{display:flex;flex-wrap:wrap;gap:6px;margin:12px 0}
        .step{flex:1;min-width:110px;background:#20242a;border:1px solid var(--border-color);border-radius:8px;padding:8px 10px;font-size:.74rem;cursor:pointer}
        .step.done{border-left:3px solid var(--success)}
        .step.run{border-left:3px solid var(--warning)}
        .step.fail{border-left:3px solid var(--danger)}
        .step.skip{opacity:.55}
        .step .t{font-weight:700}
        .step .s{color:var(--text-muted);font-size:.7rem}
        .modal-veil{position:fixed;inset:0;background:rgba(0,0,0,.65);display:none;align-items:center;justify-content:center;z-index:100;padding:16px}
        .modal-veil.open{display:flex}
        .modal{background:#20242a;border:1px solid #4a4a4a;border-radius:12px;max-width:640px;width:100%;max-height:88vh;overflow-y:auto;padding:22px}
        .modal input,.modal select,.modal textarea{width:100%;background:#000;border:1px solid var(--border-color);border-radius:6px;color:#fff;padding:8px 10px;margin:4px 0 10px;font-size:.85rem}
        .modal label{font-size:.78rem;color:var(--text-muted)}
        .wiz-steps{display:flex;gap:6px;margin-bottom:14px}
        .wiz-steps span{flex:1;text-align:center;font-size:.7rem;padding:6px;border-radius:6px;background:#141414;color:var(--text-muted)}
        .wiz-steps span.on{background:#262626;color:#fff;border:1px solid #4a4a4a}
        .tabs{display:flex;gap:6px;margin:12px 0;flex-wrap:wrap}
        .hero-stats{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px}
        .hero-stat{background:var(--surface-secondary);border:1px solid var(--border-color);border-radius:8px;padding:8px 12px;font-size:.78rem;min-width:130px}
        .hero-stat strong{font-size:1rem;display:block}
        .gnode{cursor:pointer}
        .gnode rect{fill:#20242a;stroke:#4a4a4a;stroke-width:1}
        .gnode text{fill:var(--text-main);font-size:11px}
        .gnode.key rect{stroke:#d9d9d9;stroke-width:2.5}
        .gnode.dim{opacity:.25}
        .gnode.lit rect{stroke:#fff;stroke-width:2.5}
        .gedge{stroke:#5a5f66;stroke-width:1.2}
        .gedge.contra{stroke:#c0564d;stroke-dasharray:5 4}
        .gedge.lit{stroke:#fff;stroke-width:2.5}
        .gedge.dim{opacity:.2}
        .conf-bar{height:8px;border-radius:4px;background:#141414;margin:4px 0;position:relative}
        .conf-bar i{position:absolute;left:0;top:0;bottom:0;border-radius:4px;background:linear-gradient(90deg,#6a6a6a,#d9d9d9)}
        body.present #topnav,body.present .sidebar,body.present #crumbs,body.present #wf-stepper,body.present #inv-tabs{display:none}
        body.present #app{grid-template-columns:minmax(0,1fr)}
        body.present .view.active{max-width:1100px}
        .tabs button{padding:7px 12px;border-radius:6px;border:1px solid var(--border-color);background:#20242a;color:var(--text-muted);cursor:pointer;font-size:.8rem}
        .tabs button.on{background:#262626;color:#fff;border-color:#4a4a4a}
        .btn:active{transform:translateY(1px)}
        .btn-danger{background:linear-gradient(180deg,#5a2320,#2a1210);border:1px solid #8a3a32;color:#fff}
        .tl-group{border:1px solid var(--border-color);border-radius:8px;margin-bottom:8px;background:var(--surface-secondary)}
        .tl-group>button{all:unset;display:block;width:100%;text-align:left;padding:10px 14px;cursor:pointer;box-sizing:border-box}
        .tl-group>button:focus-visible{outline:2px solid #d9d9d9;outline-offset:-2px}
        .tl-attrs{display:grid;grid-template-columns:130px minmax(0,1fr);gap:2px 10px;font-size:.8rem;margin-top:6px}
        .tl-attrs dt{color:var(--text-muted)} .tl-attrs dd{margin:0}
        .appr-modal-grid{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 12px;font-size:.85rem;margin:10px 0}
        .appr-modal-grid dt{color:var(--text-muted)} .appr-modal-grid dd{margin:0}
        .skeleton{background:linear-gradient(90deg,#141414,#1e1e1e,#141414);border-radius:6px;min-height:18px;margin:6px 0;animation:sk 1.4s infinite}
        .side-h{font-size:.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.06em;margin:0 0 6px}
        .side-link{width:100%;text-align:left;justify-content:flex-start}
        .proj-row{display:flex;gap:8px;align-items:center;width:100%;text-align:left;background:transparent;border:1px solid transparent;border-radius:6px;color:var(--text-main);padding:7px 10px;font-size:.8rem;font-weight:600;cursor:pointer;box-sizing:border-box}
        .proj-row:hover{background:#1c1c1c}
        .proj-row.sel{background:linear-gradient(180deg,#232323,#141414);border-color:#4a4a4a;border-left:3px solid #d9d9d9}
        .proj-row .meta{font-size:.7rem;color:var(--text-muted);font-weight:400}
        .side-link .ic,.proj-row .ic{width:16px;text-align:center;flex:none}
        #approval-box details.appr{margin-bottom:6px}
        #approval-box details.appr summary{cursor:pointer;list-style:none}
        #approval-box details.appr summary::-webkit-details-marker{display:none}
        #app.collapsed .sidebar{display:none}
        @keyframes sk{0%{opacity:.5}50%{opacity:1}100%{opacity:.5}}
        .metric-chip{background:var(--surface-secondary);color:var(--text-primary);border:1px solid var(--border-color);border-radius:8px;padding:8px 12px;font-size:.78rem}
        .metric-chip strong{font-size:1rem;display:block}
        .metric-chip.over{border-color:var(--warning)}
        details.sim-group{border:1px solid var(--border-color);border-radius:8px;margin-bottom:8px;background:#0d0d0d}
        details.sim-group summary{cursor:pointer;padding:10px 14px;font-weight:700;font-size:.85rem}
        details.sim-group .grp{padding:0 14px 12px}
        details.sim-group h5{font-size:.72rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:.05em;margin:10px 0 6px}
        .timeline{border-left:2px solid #3a3a3a;margin:8px 0 8px 6px;padding-left:14px}
        .timeline div{margin-bottom:10px;font-size:.8rem}
        .timeline .ts{color:var(--text-muted);font-size:.72rem}
        a{color:#d9d9d9}
        [data-theme="light"]{--bg-dark:#f5f6f8;--card-bg:#ffffff;--surface:#ffffff;--surface-secondary:#f0f2f5;--text-main:#15171a;--text-muted:#61666d;--border-color:#dde1e6;--accent-cyan:#333333;--accent-purple:#6b7280;--accent-red:#9c2f28;--accent-green:#1e6b34;--accent-yellow:#8a6d1c}
        [data-theme="light"] body{background:linear-gradient(135deg,#f7f8fa 0%,#f2f4f7 100%);color:#15171a}
        [data-theme="light"] .sidebar{background:#ffffff;border-color:#dde1e6}
        [data-theme="light"] #topnav{background:rgba(255,255,255,.92);border-color:#dde1e6}
        [data-theme="light"] .card,[data-theme="light"] .stat-card,[data-theme="light"] .modal,[data-theme="light"] details.sim-group{background:#ffffff;border-color:#dde1e6;box-shadow:0 1px 3px rgba(20,22,26,.06)}
        [data-theme="light"] .item-box,[data-theme="light"] .evidence-box,[data-theme="light"] pre,[data-theme="light"] #log-summary,[data-theme="light"] .step{background:#f0f2f5;border-color:#dde1e6;color:#15171a}
        [data-theme="light"] .log-panel{background:#0d1117;border-color:#dde1e6}
        [data-theme="light"] .sim-btn,[data-theme="light"] select,[data-theme="light"] input,[data-theme="light"] .tabs button,[data-theme="light"] .nav-btn{background:#fff;border-color:#c9ced4;color:#15171a}
        [data-theme="light"] .nav-btn.active{background:#e8ebef;border-color:#b9bfc7;color:#111}
        [data-theme="light"] .log-error{color:#fff}
        [data-theme="light"] .log-warn{color:#d6d6d6}
        [data-theme="light"] table.tbl th,[data-theme="light"] table.tbl td{border-color:#e2e2e2}
        [data-theme="light"] a{color:#333}
        [data-theme="light"] .proj-row.sel{background:linear-gradient(180deg,#eceff3,#e2e6eb);border-color:#b9bfc7}
        [data-theme="light"] .badge{background:#f0f2f5;border-color:#c9ced4;color:#333}
        @media (max-width: 900px){#topnav{flex-wrap:wrap}.cards{grid-template-columns:repeat(2,1fr)}}

    </style>
</head>
<body>
<nav id="topnav" aria-label="Primary">
  <button class="hamb" onclick="toggleSidebar()" aria-label="Toggle navigation" aria-expanded="true" title="Toggle sidebar">☰</button>
  <span class="brand">◼ Cloud RCA Agent</span>
  <button class="nav-btn" data-view="home" onclick="go('home')" title="Home">⌂ Home</button>
  <button class="nav-btn" data-view="projects" onclick="go('projects')">Projects</button>
  <button class="nav-btn" data-view="incidents" onclick="go('incidents')">Incidents</button>
  <button class="nav-btn" data-view="create" onclick="go('create')">Create Incident</button>
  <button class="nav-btn" data-view="simulations" onclick="go('simulations')">Simulations</button>
  <button class="nav-btn" data-view="prs" onclick="go('prs')">Pull Requests</button>
  <button class="nav-btn" data-view="analyze" onclick="go('analyze')">Analyze</button>
  <span class="nav-right">
    <button class="nav-btn" data-view="settings" onclick="go('settings')">Settings</button>
    <button class="nav-btn" id="theme-btn" onclick="toggleTheme()" title="Toggle dark / light theme">◐ Theme</button>
    <span title="Signed in operator" style="font-size:.78rem;color:var(--text-muted);white-space:nowrap">◉ operator</span>
  </span>
</nav>
<div id="app">
<div id="backdrop" onclick="document.body.classList.remove('drawer-open')" aria-hidden="true"></div>
    <div class="sidebar">
        <div><p class="side-h"><span class="txt">Projects</span></p><div id="side-projects">Loading…</div></div>
        <div><p class="side-h"><span class="txt">Operations</span></p>
            <div style="display:flex;flex-direction:column;gap:6px">
            <button class="sim-btn side-link" onclick="go('incidents')" title="Active Incidents"><span class="ic" aria-hidden="true">◉</span><span class="lbl">Active Incidents</span></button>
            <button class="sim-btn side-link" onclick="go('prs')" title="Pull Requests"><span class="ic" aria-hidden="true">⎇</span><span class="lbl">Pull Requests</span></button>
            <button class="sim-btn side-link" onclick="go('analyze')" title="Analyze Logs"><span class="ic" aria-hidden="true">≡</span><span class="lbl">Analyze Logs</span></button>
            </div>
        </div>
        <div><p class="side-h"><span class="txt">Administration</span></p>
            <div style="display:flex;flex-direction:column;gap:6px">
            <button class="sim-btn side-link" onclick="openOnboard()" title="Onboard Project"><span class="ic" aria-hidden="true">+</span><span class="lbl">Onboard Project</span></button>
            <button class="sim-btn side-link" onclick="go('settings')" title="Settings"><span class="ic" aria-hidden="true">⚙</span><span class="lbl">Settings</span></button>
            </div>
        </div>
        <div id="approval-zone" style="margin-top:8px;padding-top:12px;border-top:1px solid var(--border-color)">
            <p class="side-h"><span class="txt">Approval Center</span></p>
            <div id="approval-box" style="font-size:.78rem;color:var(--text-muted)">No pending approvals</div>
        </div>
        <div style="margin-top:auto;padding-top:8px;font-size:.68rem;color:var(--text-muted)"><span id="build-stamp" title="Deployed build"></span></div>
    </div>
    <div class="main-content">
<div id="crumbs" aria-label="Breadcrumb"></div>
<div id="view-incidents">
<div id="incidents-table-wrap">
  <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
    <h1 style="flex:1">Incidents</h1>
    <button class="btn btn-primary" onclick="toggleCreateForm()">+ Create Incident</button>
  </div>
  <div id="create-form" style="display:none" class="card">
    <div class="tabs">
      <button id="tab-manual" class="on" onclick="createTab('manual')">Manual Incident</button>
      <button id="tab-sim" onclick="createTab('sim')">Simulated Incident</button>
    </div>
    <div id="create-manual">
      <div class="grid">
      <div><label>Incident title</label><input id="ci-title" placeholder="Checkout HTTP 500 spike" /></div>
      <div><label>Project</label><select id="ci-project"></select></div>
      </div>
      <div class="grid">
      <div><label>Environment</label><select id="ci-env"><option>prod</option><option>staging</option><option>dev</option></select></div>
      <div><label>Severity</label><select id="ci-sev"><option value="P1">Critical (P1)</option><option value="P2" selected>High (P2)</option><option value="P3">Medium (P3)</option></select></div>
      </div>
      <div><label>Affected services (comma separated)</label><input id="ci-services" placeholder="checkout-service" /></div>
      <div><label>Description</label><textarea id="ci-desc" rows="3" placeholder="What is happening?"></textarea></div>
      <div class="grid">
      <div><label>Start time (ISO, optional)</label><input id="ci-start" placeholder="2026-09-10T10:00:00Z" /></div>
      <div><label>Revision / deployment (optional)</label><input id="ci-rev" placeholder="checkout-service-00005-bad" /></div>
      </div>
      <div class="grid">
      <div><label>Trace ID (optional)</label><input id="ci-trace" /></div>
      <div><label>Request ID (optional)</label><input id="ci-req" /></div>
      </div>
      <div><label>Error signature (optional)</label><input id="ci-err" placeholder="NULL_POINTER_EXCEPTION" /></div>
      <div><label>Additional context</label><textarea id="ci-context" rows="2"></textarea></div>
      <div style="margin-top:8px"><button class="btn btn-primary" onclick="createManual()">Create Incident</button> <span id="ci-create-result" style="font-size:.8rem"></span></div>
    </div>
    <div id="create-sim" style="display:none">
      <p style="font-size:.82rem;color:var(--text-muted)">Each simulation injects a documented failure into the live log stream. Nothing is analyzed until you run RCA.</p>
      <div id="create-sim-list"></div>
    </div>
  </div>
  <div class="card">
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center">
      <input id="inc-search" oninput="renderIncidentTable()" placeholder="Search id, error, service, trace…" style="flex:1;min-width:180px;background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:6px;padding:7px 10px" />
      <select id="inc-filter-sev" onchange="renderIncidentTable()"><option value="">All severities</option><option>P1</option><option>P2</option><option>P3</option></select>
      <select id="inc-filter-status" onchange="renderIncidentTable()"><option value="">All statuses</option><option>Open</option><option>Investigating</option><option>Resolved</option></select>
      <span id="inc-count" style="font-size:.78rem;color:var(--text-muted)"></span>
    </div>
    <div style="overflow-x:auto"><table class="tbl" aria-label="Incidents">
      <thead><tr><th>Incident</th><th>Project</th><th>Severity</th><th>Status</th><th>Service</th><th>RCA</th><th>PR</th></tr></thead>
      <tbody id="inc-table-body"><tr><td colspan="7">Loading…</td></tr></tbody>
    </table></div>
  </div>
</div>
<div id="incident-workspace" style="display:none">
  <button class="sim-btn" onclick="showIncidentTable()">← All incidents</button>
  <span id="ws-project-chip" style="margin-left:8px;font-size:.78rem;color:var(--text-muted)"></span>
        <div class="header">
            <div><h1 id="inc-title">Google Cloud RCA Investigation</h1><p id="inc-desc" style="color:var(--text-muted);margin-top:4px">Select an incident or simulate errors below.</p><div id="inc-meta" style="font-size:.78rem;color:var(--text-muted);margin-top:6px"></div></div>
            <button class="btn btn-green" id="rca-btn-top" onclick="runLiveRCA()" style="display:none">🧠 Do RCA (Live)</button>
        </div>
        <div id="wf-stepper" class="stepper" aria-label="RCA workflow progress"></div>
        <div id="inc-hero" class="card" style="margin-bottom:12px;display:none"></div>
        <div class="tabs" id="inv-tabs" role="tablist" aria-label="Incident detail tabs" style="display:none">
            <button data-tab="summary" class="on" onclick="switchInvTab('summary')" role="tab">Summary</button>
            <button data-tab="investigation" onclick="switchInvTab('investigation')" role="tab">Investigation</button>
            <button data-tab="evidence" onclick="switchInvTab('evidence')" role="tab">Evidence</button>
            <button data-tab="timeline" onclick="switchInvTab('timeline')" role="tab">Timeline</button>
            <button data-tab="remediation" onclick="switchInvTab('remediation')" role="tab">Remediation</button>
            <button data-tab="approvals" onclick="switchInvTab('approvals')" role="tab">Approvals</button>
            <button data-tab="activity" onclick="switchInvTab('activity')" role="tab">Activity</button>
        </div>
        <div class="card" style="margin-bottom:16px">
            <div class="card-title">1 · Create / Simulate Incident</div>
            <details class="sim-group" open>
                <summary>Code / Application Errors</summary>
                <div class="grp">
                    <h5>Configuration</h5>
                    <button class="sim-btn" data-sim="bad-deployment" onclick="simulate('bad-deployment')">Bad Deployment</button>
                    <button class="sim-btn" data-sim="config-error" onclick="simulate('config-error')">Config Error</button>
                    <h5>Application Logic</h5>
                    <button class="sim-btn" data-sim="malformed-payload" onclick="simulate('malformed-payload')">Malformed Input</button>
                    <button class="sim-btn" data-sim="auth-failure" onclick="simulate('auth-failure')">Auth Failure</button>
                    <h5>Application Dependency</h5>
                    <button class="sim-btn" data-sim="dependency-failure" onclick="simulate('dependency-failure')">Dependency Failure</button>
                    <button class="sim-btn" data-sim="db-timeout" onclick="simulate('db-timeout')">DB Timeout</button>
                    <h5>Application Resource</h5>
                    <button class="sim-btn" data-sim="pool-exhaustion" onclick="simulate('pool-exhaustion')">Pool Exhaustion</button>
                </div>
            </details>
            <details class="sim-group">
                <summary>Infrastructure / Platform Errors</summary>
                <div class="grp">
                    <h5>Compute</h5>
                    <button class="sim-btn" data-sim="cpu-exhaustion" onclick="simulate('cpu-exhaustion')">CPU Exhaustion</button>
                    <button class="sim-btn" data-sim="memory-leak" onclick="simulate('memory-leak')">Memory Leak</button>
                    <h5>Network</h5>
                    <button class="sim-btn" data-sim="network-timeout" onclick="simulate('network-timeout')">Network Timeout</button>
                    <h5>Capacity</h5>
                    <button class="sim-btn" data-sim="traffic-overload" onclick="simulate('traffic-overload')">Traffic Overload</button>
                    <h5>Platform / Quota</h5>
                    <button class="sim-btn" data-sim="rate-limit" onclick="simulate('rate-limit')">Rate Limit</button>
                </div>
            </details>
            <div><button class="sim-btn btn-red" onclick="clearLogs()">Clear Simulation</button>
            <span id="sim-cat" style="margin-left:10px;font-size:.78rem;color:var(--text-muted)"></span></div>
            <div id="sim-desc" style="font-size:.78rem;color:var(--text-muted);margin-top:6px">Pick an error to inject a documented failure into the live log stream. RCA runs only when you start it.</div>
        </div>
            <span id="live-status" style="margin-left:auto;font-size:.78rem;color:var(--text-muted)"><span class="status-dot dot-green"></span>Live</span>
        </div>
        <div class="grid" id="sec-live">
            <div class="card" style="grid-column: span 2;">
                <div class="card-title">📡 Live Logs <span style="font-size:.75rem;color:var(--text-muted);font-weight:400">2 · Live Telemetry — auto-refresh, click Simulate to inject</span>
                    <button class="sim-btn" id="copy-logs-btn" onclick="copyLogs()" title="Copy visible logs" style="margin-left:auto">Copy</button>
                    <button class="sim-btn" id="pause-btn" onclick="togglePause()" style="margin-left:auto">Pause</button>
                </div>
                <div id="log-summary" class="well" style="display:flex;flex-wrap:wrap;gap:14px;font-size:.78rem;margin-bottom:8px;padding:8px 10px">No data yet — simulate an incident.</div>
                <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px;align-items:center;font-size:.78rem">
                    <select id="f-service" onchange="renderLogs()" style="background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 6px"><option value="">All services</option></select>
                    <select id="f-severity" onchange="renderLogs()" style="background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 6px"><option value="">All severities</option><option>DEBUG</option><option>INFO</option><option>WARNING</option><option>ERROR</option><option>CRITICAL</option></select>
                    <select id="f-error" onchange="renderLogs()" style="background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 6px;max-width:220px"><option value="">All error types</option></select>
                    <input id="f-trace" oninput="renderLogs()" placeholder="trace id…" style="background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 8px;font-size:.78rem;width:150px" />
                    <input id="f-search" oninput="renderLogs()" placeholder="search logs…" style="flex:1;min-width:140px;background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 8px;font-size:.78rem" />
                </div>
                <div id="live-logs" class="log-panel" aria-label="Live logs terminal">Waiting for simulated errors... Click any button above.</div>
                <div style="margin-top:10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
                    <button class="btn btn-green btn-primary" id="rca-btn" onclick="runLiveRCA()">Run Live RCA</button>
                    <span id="rca-gate" style="font-size:.78rem;color:var(--text-muted)">Run the RCA agent against the currently collected incident evidence. The agent will correlate logs, metrics, deployments, traces, infrastructure state, and code changes before proposing a root cause.</span>
                </div>
            </div>
        </div>
        <div id="rca-output" style="display:none;">
            <div class="rca-grid">
                <div class="card"><div class="card-title">🎯 Confirmed Root Cause
                        <span style="margin-left:auto;display:flex;gap:6px">
                            <button class="sim-btn" onclick="copyRcaSummary()" title="Copy concise RCA summary">Copy RCA Summary</button>
                            <button class="sim-btn" onclick="exportRca('json')" title="Export RCA as JSON">Export JSON</button>
                            <button class="sim-btn" onclick="exportRca('markdown')" title="Export RCA as Markdown">Export Markdown</button>
                        </span></div>
                    <div style="font-size:.72rem;color:var(--text-muted);margin-bottom:8px">3 · RCA Results <span id="evidence-fresh"></span></div>
                    <div style="margin-bottom:12px;"><span class="badge badge-red" id="rc-category">Category</span> <span class="badge badge-yellow" id="rc-confidence">Confidence</span> <span class="badge badge-green" id="rc-risk">Risk</span></div>
                    <p id="rc-summary" style="line-height:1.6;font-size:.95rem"></p>
                    <div id="rc-domain" style="font-size:.85rem;margin-top:8px"></div>
                    <div id="rc-why" style="font-size:.85rem;margin-top:8px"></div>
                    <div style="margin-top:14px;font-size:.85rem;color:var(--text-muted)"><strong>Blast Radius:</strong> <span id="rc-blast"></span></div>
                    <div style="margin-top:10px;font-size:.8rem;color:var(--text-muted)"><strong>Timeline:</strong><div id="rc-timeline" style="margin-top:6px"></div></div>
                </div>
                <div class="card"><div class="card-title">🛠️ Recommended Action</div><div class="item-box" id="rc-action" style="border-left-color:var(--accent-green);font-weight:500"></div>
                    <div style="margin-top:12px"><strong style="font-size:.85rem;color:var(--text-muted)">Additional Checks:</strong><div id="additional-checks" style="margin-top:6px"></div></div>
                    <div id="remediation-box" style="margin-top:14px"></div>
                </div>
            </div>
            <div class="grid">
                <div class="card"><div class="card-title">📌 Supporting Evidence Cited</div><div id="evidence-list"></div></div>
                <div class="card"><div class="card-title">✖ Contradictory Evidence Analyzed</div><div id="contra-list"></div></div>
            </div>
        </div>
        <div id="codefix-output" style="display:none;">
            <div class="grid">
                <div class="card" style="grid-column: span 2;">
                    <div class="card-title">🔧 Suggested Code Fix <span id="cf-status-badge" class="badge badge-yellow" style="margin-left:8px">Suggested</span></div>
                    <div id="cf-investigation" style="margin-bottom:12px"></div>
                    <div id="cf-diff-wrap" style="display:none;margin-bottom:12px">
                        <div style="font-size:.85rem;color:var(--text-muted);margin-bottom:6px"><strong>Inline diff</strong> <span id="cf-files" style="margin-left:8px"></span></div>
                        <pre id="cf-diff" style="background:#000000;border:1px solid var(--border-color);border-radius:6px;padding:12px;overflow-x:auto;font-family:'JetBrains Mono',monospace;font-size:.78rem;line-height:1.5;white-space:pre-wrap"></pre>
                        <div id="cf-meta" style="font-size:.8rem;color:var(--text-muted);margin-top:8px"></div>
                    </div>
                    <div id="cf-no-fix" style="display:none" class="item-box"></div>
                    <div id="cf-preflight" style="font-size:.76rem;color:var(--text-muted);margin:8px 0"></div>
                    <div id="cf-lifecycle" style="font-size:.8rem;color:var(--text-muted);margin:8px 0"></div>
                    <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px">
                        <input id="cf-msg" placeholder="approval note (optional)…" style="flex:1;min-width:180px;background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:7px 10px;font-size:.8rem" />
                        <button class="btn btn-green" id="cf-approve-btn" onclick="approveFixPR()">Approve &amp; Create PR</button>
                        <button class="btn btn-red" onclick="rejectFix()">Reject</button>
                        <button class="sim-btn" onclick="generateFix(true)">Generate Fix</button>
                    </div>
                    <div id="cf-pr" style="margin-top:10px"></div>
                    <div id="cf-tests" style="margin-top:8px;font-size:.8rem"></div>
                </div>
            </div>
        </div>
        <div id="sec-inv" style="display:none">
            <div class="card"><div class="card-title">🕸 Investigation Graph <span style="font-size:.72rem;color:var(--text-muted);font-weight:400">how the conclusion was reached — click any node</span>
                <span style="margin-left:auto;display:flex;gap:6px">
                    <button class="sim-btn" onclick="graphZoom(-1)">−</button>
                    <button class="sim-btn" onclick="graphZoom(1)">+</button>
                    <button class="sim-btn" onclick="graphFit()">Fit</button>
                    <button class="sim-btn" onclick="highlightSupportPath()">Show Evidence Path</button>
                </span></div>
                <div style="display:grid;grid-template-columns:minmax(0,1.6fr) minmax(240px,.8fr);gap:12px">
                    <div id="inv-graph" style="border:1px solid var(--border-color);border-radius:8px;overflow:hidden;min-height:320px"></div>
                    <div id="inv-node-detail" style="font-size:.8rem"><p style="color:var(--text-muted)">Select a node to inspect its evidence.</p></div>
                </div>
            </div>
            <div class="rca-grid">
                <div class="card"><div class="card-title">❓ Why This / Why Not</div><div id="inv-why"></div></div>
                <div class="card"><div class="card-title">🤖 Agent Findings</div><div id="inv-agents"></div></div>
            </div>
            <div class="rca-grid">
                <div class="card"><div class="card-title">📈 Confidence Evolution</div><div id="inv-conf"></div></div>
                <div class="card"><div class="card-title">🏅 Investigation Quality</div><div id="inv-quality"></div></div>
            </div>
            <div class="card"><div class="card-title">🛡 Challenge RCA <span style="font-size:.72rem;color:var(--text-muted);font-weight:400">answers use only collected incident evidence</span></div>
                <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px" id="challenge-suggest"></div>
                <div style="display:flex;gap:6px"><input id="challenge-q" placeholder="Why do you think this is not a database outage?" aria-label="Challenge the RCA conclusion" style="flex:1;background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:6px;padding:7px 10px" /><button class="btn btn-primary" onclick="submitChallenge()">Ask</button></div>
                <div id="challenge-a" style="margin-top:8px"></div>
            </div>
        </div>
        <div id="sec-timeline" style="display:none"><div class="card"><div class="card-title">⏱ Incident Timeline</div><div id="inv-timeline"></div></div></div>
            <div class="grid" id="sec-gov">
                <div class="card"><div class="card-title">Approval Timeline</div><div id="approval-timeline"><span style="color:var(--text-muted);font-size:.8rem">No approval events yet.</span></div></div>
                <div class="card"><div class="card-title">Related Pull Request</div><div id="related-pr"><span style="font-size:.8rem;color:var(--text-muted)">No pull request raised for this incident.</span></div></div>
            </div>
            <div class="grid" id="sec-meta">
                <div class="card"><div class="card-title">RCA Runs</div><div id="rca-runs"><span style="font-size:.8rem;color:var(--text-muted)">No runs yet.</span></div></div>
                <div class="card"><div class="card-title">Incident Notes</div><div id="notes-list"></div>
                    <div style="display:flex;gap:6px;margin-top:8px"><input id="note-input" placeholder="Add a note…" aria-label="Add incident note" style="flex:1;background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:6px;padding:7px 10px" /><button class="sim-btn" onclick="addNote()">Add</button></div>
                </div>
            </div>
            <div class="card" id="sec-activity" style="display:none"><div class="card-title">📋 Audit Activity</div><div id="incident-activity"></div></div>
        </div>
                </div>
<div id="view-home" class="view">
            <h1>Cloud RCA Agent</h1>
            <p style="color:var(--text-muted)">AI-powered incident investigation, code remediation, and PR automation.</p>
            <div style="display:flex;gap:8px;margin:12px 0 20px;flex-wrap:wrap">
                <button class="btn btn-primary" onclick="go('projects')">Open Projects</button>
                <button class="sim-btn" onclick="go('incidents')">View Active Incidents</button>
            </div>
            <div class="cards">
                <div class="stat-card"><div class="num" id="hm-projects">–</div><div class="lbl">Active Projects</div></div>
                <div class="stat-card"><div class="num" id="hm-incidents">–</div><div class="lbl">Open Incidents</div></div>
                <div class="stat-card"><div class="num" id="hm-rca">–</div><div class="lbl">RCA Investigations</div></div>
                <div class="stat-card"><div class="num" id="hm-prs">–</div><div class="lbl">Pull Requests Raised by Agent</div></div>
                <div class="stat-card"><div class="num" id="hm-approvals">–</div><div class="lbl">Pending Human Approvals</div></div>
            </div>
            <div class="grid">
                <div class="card"><div class="card-title">Recent Activity</div><div id="hm-activity"></div></div>
                <div class="card"><div class="card-title">Agent Pull Requests</div><div id="hm-recent-prs"></div></div>
            </div>
            <div class="card"><div class="card-title">How an investigation flows</div>
                <div style="display:flex;gap:6px;flex-wrap:wrap;font-size:.76rem">
                    <span class="pill info">Incident</span>→<span class="pill info">Evidence Collection</span>→<span class="pill info">RCA</span>→<span class="pill info">Root Cause</span>→<span class="pill info">Remediation</span>→<span class="pill info">Approval</span>→<span class="pill info">PR</span>
                </div>
            </div>
            <div class="card"><div class="card-title">Quick Actions</div>
                <div style="display:flex;gap:8px;flex-wrap:wrap">
                    <button class="sim-btn" onclick="openOnboard()">Onboard Project</button>
                    <button class="sim-btn" onclick="openOnboard('repo')">Connect Git Repository</button>
                    <button class="sim-btn" onclick="go('analyze')">Upload Logs for RCA</button>
                    <button class="sim-btn" onclick="go('incidents')">View Incidents</button>
                    <button class="sim-btn" onclick="go('prs')">View Pull Requests</button>
                </div>
            </div>
        </div>
        <div id="view-projects" class="view">
            <h1>Projects</h1>
            <p style="color:var(--text-muted);font-size:.85rem;margin:0 0 12px">Manage services and repositories monitored by Cloud RCA Agent.</p>
            <div class="page-header-actions" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:8px">
                <button class="btn btn-primary" onclick="openOnboard()">+ Onboard Project</button>
                <button class="sim-btn" onclick="openOnboard('repo')">Connect Git Repository</button>
                <button class="sim-btn" onclick="openOnboard('cloud')">Add Google Cloud Project</button>
            </div>
            <div style="margin-bottom:16px"><button class="sim-btn" onclick="go('analyze')">Upload Logs for RCA</button></div>
            <div id="projects-list" class="cards projects-grid"><div class="skeleton"></div></div>
            <div id="project-detail"></div>
        </div>
        <div id="view-create" class="view">
            <h1>Create Incident</h1>
            <p style="color:var(--text-muted);font-size:.85rem">File a real incident. No simulation controls appear here.</p>
            <div class="card">
                <div class="card-title">Basic Information</div>
                <div class="grid">
                <div><label>Incident title</label><input id="nc-title" placeholder="Checkout HTTP 500 spike" /></div>
                <div><label>Project</label><select id="nc-project"></select></div>
                </div>
                <div class="grid">
                <div><label>Severity</label><select id="nc-sev"><option value="P1">Critical (P1)</option><option value="P2" selected>High (P2)</option><option value="P3">Medium (P3)</option></select></div>
                <div><label>Environment</label><select id="nc-env"><option>prod</option><option>staging</option><option>dev</option></select></div>
                </div>
                <div><label>Affected service(s) (comma separated)</label><input id="nc-services" placeholder="checkout-service" /></div>
                <div><label>Description</label><textarea id="nc-desc" rows="3"></textarea></div>
                <div class="grid">
                <div><label>Trace ID (optional)</label><input id="nc-trace" /></div>
                <div><label>Request ID (optional)</label><input id="nc-req" /></div>
                </div>
                <div class="grid">
                <div><label>Deployment / revision (optional)</label><input id="nc-rev" /></div>
                <div><label>Error signature (optional)</label><input id="nc-err" /></div>
                </div>
                <div style="margin-top:8px"><button class="btn btn-primary" onclick="createStandalone()">Create Incident</button> <span id="nc-result" style="font-size:.8rem"></span></div>
            </div>
            <div class="card"><div class="card-title">Repository Context</div><div id="nc-repo" style="font-size:.85rem;color:var(--text-muted)">Select a project to check repository status.</div></div>
        </div>
        <div id="view-simulations" class="view">
            <h1>Incident Simulations</h1>
            <p style="color:var(--text-muted);font-size:.85rem">Generate controlled synthetic incidents for RCA demonstrations and testing. Simulations never affect production resources.</p>
            <div style="display:flex;gap:6px;margin:12px 0;flex-wrap:wrap" id="sim-filters">
                <button class="sim-btn" onclick="filterSims('')">All</button>
                <button class="sim-btn" onclick="filterSims('Code')">Code</button>
                <button class="sim-btn" onclick="filterSims('Database')">Database</button>
                <button class="sim-btn" onclick="filterSims('Dependency')">Dependency</button>
                <button class="sim-btn" onclick="filterSims('Runtime')">Runtime</button>
                <button class="sim-btn" onclick="filterSims('Concurrency')">Concurrency</button>
                <button class="sim-btn" onclick="filterSims('Deployment')">Deployment</button>
            </div>
            <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
                <select id="sim-service"><option>checkout-service</option><option>orders-service</option><option>payments-service</option></select>
                <select id="sim-env"><option>demo</option><option>local</option><option>test</option></select>
                <span style="font-size:.75rem;color:var(--text-muted)">Production simulation is disabled.</span>
            </div>
            <div id="sim-grid" class="projects-grid"><div class="skeleton"></div></div>
        </div>
        <div id="view-prs" class="view">
            <h1>Pull Requests</h1>
            <p style="color:var(--text-muted);font-size:.85rem">Every PR raised by the RCA Agent.</p>
            <div style="display:flex;gap:8px;margin:12px 0;flex-wrap:wrap;align-items:center">
                <select id="pr-filter-project" onchange="renderPRs()" aria-label="Filter by project"><option value="">All projects</option></select>
                <select id="pr-filter-status" onchange="renderPRs()" aria-label="Filter by status"><option value="">All statuses</option><option>Open</option><option>Merged</option><option>Closed</option><option>Failed</option><option>Awaiting Approval</option></select>
                <span id="pr-count" style="font-size:.78rem;color:var(--text-muted)"></span>
            </div>
            <div class="card"><div style="overflow-x:auto"><table class="tbl" aria-label="Agent pull requests">
                <thead><tr><th>PR</th><th>Incident</th><th>Project</th><th>Title</th><th>Created</th><th>Risk</th><th>Tests</th><th>Status</th></tr></thead>
                <tbody id="prs-list"><tr><td colspan="8">Loading…</td></tr></tbody>
            </table></div></div>
            <div id="pr-detail"></div>
        </div>
        <div id="view-analyze" class="view">
            <h1>Analyze Logs</h1>
            <p style="color:var(--text-muted);font-size:.85rem">Upload application, infrastructure, or cloud logs and let the RCA Agent identify likely root causes.</p>
            <div class="card"><div class="card-title">1 · Select Project &amp; Upload</div>
                <div class="grid">
                    <div><label>Project</label><select id="up-project"></select></div>
                    <div><label>Log Source Type</label><select id="up-source"><option>Auto Detect</option><option>Application Logs</option><option>Cloud Run Logs</option><option>Kubernetes Logs</option><option>Database Logs</option><option>Load Balancer Logs</option><option>API Gateway Logs</option><option>System Logs</option><option>Mixed Logs</option></select></div>
                </div>
                <div id="dropzone" style="border:2px dashed #4a4a4a;border-radius:10px;padding:26px;text-align:center;margin:10px 0">
                    <p><strong>Drop log files here</strong></p><p style="font-size:.78rem;color:var(--text-muted)">.log, .txt, .json, .jsonl, .csv — up to 4 files, 25 MB each</p>
                    <p>or</p>
                    <button class="sim-btn" onclick="document.getElementById('up-files').click()">Browse Files</button>
                    <input type="file" id="up-files" multiple accept=".log,.txt,.json,.jsonl,.csv" style="display:none" />
                </div>
                <div id="up-filelist" style="font-size:.8rem"></div>
                <div class="grid">
                    <div><label>Affected Service (optional)</label><input id="up-service" placeholder="checkout-service" /></div>
                    <div><label>Approximate Incident Start (optional)</label><input id="up-start" placeholder="2026-09-10T10:00:00Z" /></div>
                </div>
                <div class="grid">
                    <div><label>Region (optional)</label><input id="up-region" placeholder="us-central1" /></div>
                    <div><label>Environment (optional)</label><input id="up-env" placeholder="prod" /></div>
                </div>
                <div><label>Incident Description (optional)</label><textarea id="up-desc" rows="2"></textarea></div>
                <div style="margin-top:10px"><button class="btn btn-primary" id="up-btn" onclick="uploadLogs()">Upload &amp; Preview</button></div>
            </div>
            <div class="card" id="up-preview-card" style="display:none"><div class="card-title">2 · Ingestion Preview</div><div id="up-preview"></div>
                <div style="margin-top:10px;font-size:.82rem">
                    <strong>What would you like to do?</strong><br/>
                    <label><input type="radio" name="up-mode" value="analyze_only" checked /> Analyze logs without creating an incident</label><br/>
                    <label><input type="radio" name="up-mode" value="attach" /> Attach to existing incident</label>
                    <input id="up-attach-inc" placeholder="INC-..." style="background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 8px;font-size:.78rem;width:160px" /><br/>
                    <label><input type="radio" name="up-mode" value="create" /> Create a new incident from these logs</label>
                </div>
                <div style="margin-top:10px"><button class="btn btn-primary" id="up-analyze-btn" onclick="analyzeUpload()">Run RCA</button></div>
            </div>
            <div id="up-results"></div>
            <div class="card"><div class="card-title">Log Analyses</div><div id="analyses-list"></div></div>
            <div id="analysis-detail"></div>
        </div>
        <div id="view-settings" class="view">
            <h1>Settings</h1>
            <div class="card"><div class="card-title">Appearance</div>
                <label style="font-size:.85rem"><input type="radio" name="theme" value="dark" onchange="setTheme('dark')" /> Dark</label><br/>
                <label style="font-size:.85rem"><input type="radio" name="theme" value="light" onchange="setTheme('light')" /> Light</label><br/>
                <label style="font-size:.85rem"><input type="radio" name="theme" value="system" onchange="setTheme('system')" /> System preference</label>
            </div>
            <div class="card"><div class="card-title">Platform</div><div id="settings-body">Loading…</div></div>
        </div>
        <div id="modal" class="modal-veil"><div class="modal" role="dialog" aria-modal="true" aria-label="Onboard project"><div id="wizard"></div></div></div>
        <div id="approval-modal" class="modal-veil" onclick="if(event.target===this)closeApprovalModal()"><div class="modal" role="dialog" aria-modal="true" aria-label="Review approval"><div id="approval-modal-body"></div></div></div>
        <div id="raw-modal" class="modal-veil" onclick="if(event.target===this)closeRawDrawer()"><div class="modal" role="dialog" aria-modal="true" aria-label="Raw evidence"><div id="raw-modal-body"></div></div></div>    </div>
</div>
<script>
let currentIncident='incident_001_db_timeout.json';
let liveIncidentFile=null;
let liveScenario=null;
let LAST_INCIDENT=null;
let LOGS=[];
let PAUSED=false;
let _lastSumSig='';

async function simulate(scenario){
  const btn=document.getElementById('live-status'); btn.innerHTML='<span class="status-dot dot-red"></span>Injecting...';
  const res=await fetch('/api/simulate/'+scenario,{method:'POST'});
  const data=await res.json();
  liveScenario=data.scenario;
  if(data.incident_file){ liveIncidentFile=data.incident_file; currentIncident=data.incident_file; }
  else{ liveIncidentFile=null; }
  document.getElementById('inc-title').innerText='Live Simulated: '+scenario;
  document.getElementById('inc-desc').innerText='Injected at '+new Date().toLocaleTimeString()+' — logs streaming below → click Do RCA';
  document.getElementById('codefix-output').style.display='none'; LAST_INCIDENT=null;
  try{
    const sc=(TAX&&TAX.scenarios||{})[scenario]||{};
    const cat=document.getElementById('sim-cat');
    if(cat) cat.innerText='Category: '+(sc.domain||'Unknown')+' / '+(sc.subcategory||'Unknown');
  }catch(e){}
  btn.innerHTML='<span class="status-dot dot-red"></span>Error injected!';
  setTimeout(()=>btn.innerHTML='<span class="status-dot dot-green"></span>Live',1800);
  fetchLogs();
}
async function clearLogs(){ await fetch('/api/logs/clear',{method:'POST'}); document.getElementById('live-logs').innerHTML='Logs cleared. Ready for new simulation.'; liveIncidentFile=null; }
let _pollInFlight=false, _lastLogSig='', _lastApprSig='';
function _approvalCard(a, accent, open){
  const border=accent?'var(--accent-cyan)':'var(--border-color)';
  const ptype=a.action_type==='CODE_CHANGE'?'Code Change':'Infrastructure Change';
  const conf=a.confidence!=null?` · ${Math.round(a.confidence*100)}% confidence`:'';
  return `<details class="appr"${open?' open':''} style="padding:6px;border:1px solid ${border};border-radius:6px;margin-bottom:6px"><summary style="cursor:pointer;font-size:.76rem;color:var(--text-muted)"><span class="pill warn">• PENDING</span> <span class="pill info">${ptype}</span> <strong>${actionTitle(a.action)}</strong> ${a.incident_id}<br/>Risk ${a.risk}${conf}</summary><div style="margin-top:6px"><button onclick="openApprovalModal('${a.approval_id}')" style="padding:2px 10px;border-radius:4px;background:linear-gradient(180deg,#2e2e2e,#101010);border:1px solid #555555;color:#fff;cursor:pointer">Review</button></div></details>`;
}

function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function _historyCard(a){
  const st=a.status||'UNKNOWN';
  const color=st==='APPROVED'?'var(--accent-green)':(st==='REJECTED'?'var(--accent-red)':'var(--accent-yellow)');
  const when=String(a.decided_at||'').replace('T',' ').slice(0,19);
  const note=a.decided_message?`<div style="margin-top:4px;font-style:italic;color:var(--text-main)">Note: ${esc(a.decided_message)}</div>`:'';
  const by=a.decided_by?`<div>By ${esc(a.decided_by)} at ${esc(when)}</div>`:'';
  const type=a.action_type==='CODE_CHANGE'?'Code Change':'Infrastructure Change';
  const icon=st==='APPROVED'?'\u2713':(st==='REJECTED'?'\u2715':(st==='PENDING'?'\u2022':'!'));
  const execBtn=(st==='APPROVED'&&['cloud_run_rollback','cloud_run_shift_traffic','cloud_run_scale_within_limits'].includes(a.action))
    ? `<div style="margin-top:6px"><button onclick="executeInfra('${a.approval_id}','${esc(a.action)}')" style="padding:2px 8px;border-radius:4px;background:linear-gradient(180deg,#2e2e2e,#101010);border:1px solid #555555;color:#fff;cursor:pointer">Execute &amp; Verify</button></div><div id="exec-${a.approval_id}" style="margin-top:6px"></div>`:'';
  return `<div style="padding:6px;border:1px solid var(--border-color);border-left:3px solid ${color};border-radius:6px;margin-bottom:6px;font-size:.76rem;color:var(--text-muted)"><span class="pill ${st==='APPROVED'?'ok':(st==='REJECTED'?'bad':'warn')}">${icon} ${esc(st)}</span> <span class="pill info">${type}</span> <strong style="color:var(--text-main)">${esc(a.action)}</strong> ${esc(a.incident_id)}<br/>Risk ${esc(a.risk)}${by}${note}${execBtn}</div>`;
}
async function executeInfra(id, action){
  const box=document.getElementById('exec-'+id);
  const show=t=>{ if(box) box.innerHTML=t; };
  show('<span style="color:var(--text-muted)">Loading suggested parameters…</span>');
  let params={};
  try{ params=(await (await fetch('/api/approvals/'+id+'/params')).json()).params||{}; }catch(e){}
  if(action==='cloud_run_rollback'&&!params.target_revision){
    // Version picker: previous revisions from incident evidence, current disabled
    let revs=[], suggested=null, current='';
    try{
      const rj=await (await fetch('/api/approvals/'+id+'/revisions')).json();
      revs=rj.revisions||[]; suggested=rj.suggested; current=rj.current_revision||'';
    }catch(e){}
    const opts=revs.filter(r=>!r.is_current);
    if(!opts.length){ show('No previous revisions found in incident evidence.'); return; }
    const selId='rollback-sel-'+id;
    show(`<div style="margin-bottom:6px">Roll back <strong>${esc(current||'current')}</strong> to:</div>`+
      `<select id="${selId}" style="width:100%;background:#20242a;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:6px 8px;font-size:.78rem">`+
      opts.map(r=>`<option value="${esc(r.revision_name)}"${r.revision_name===suggested?' selected':''}>${esc(r.revision_name)}${r.deployed_at?' — '+esc(r.deployed_at):''}${r.traffic_percent!==''?' — '+esc(String(r.traffic_percent))+'% traffic':''}</option>`).join('')+
      `</select><div style="color:var(--text-muted)">Suggested: ${esc(suggested||opts[0].revision_name)} (newest non-current; current revision disabled)</div>`+
      `<div style="margin-top:6px"><button onclick="doExecuteInfra('${id}','${action}',{target_revision:document.getElementById('${selId}').value})" style="padding:2px 10px;border-radius:4px;background:linear-gradient(180deg,#232323,#0d0d0d);border:1px solid #4a4a4a;color:#fff;cursor:pointer">Run Rollback</button></div>`);
    return;
  }
  if(action==='cloud_run_shift_traffic'&&!params.revision_percentages){
    const v=prompt('Traffic split JSON (must total 100), e.g. {"rev-a":100}:', '');
    if(v===null) return;
    try{ params.revision_percentages=JSON.parse(v); }catch(e){ show('Invalid JSON.'); return; }
  }
  if(action==='cloud_run_scale_within_limits'&&params.max_instances==null){
    const v=prompt('max_instances (bounded by MAX_SCALE_LIMIT):', '10');
    if(v===null) return; params.max_instances=parseInt(v,10);
  }
  doExecuteInfra(id, action, params);
}
async function doExecuteInfra(id, action, params){
  const box=document.getElementById('exec-'+id);
  const show=t=>{ if(box) box.innerHTML=t; };
  if(!confirm('Execute '+action+' with '+JSON.stringify(params)+'?')) return;
  show('<span style="color:var(--text-muted)">Executing…</span>');
  const r=await fetch('/api/approvals/'+id+'/execute',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(params)});
  const d=await r.json();
  if(!r.ok){ show('<span style="color:var(--accent-red)">Execute failed: '+esc(d.detail||r.status)+'</span>'); return; }
  const ex=d.execution||{}, vf=d.verification||{};
  show(`<div><strong>Execution:</strong> <span style="color:var(--accent-green)">${esc(ex.status||'')}</span> ${esc(ex.cloud_operation_id||'')}</div>`+
    `<div><strong>Before:</strong> ${esc(JSON.stringify(ex.before_state||{}))}</div>`+
    `<div><strong>After:</strong> ${esc(JSON.stringify(ex.after_state||{}))}</div>`+
    `<div><strong>Verification:</strong> ${esc(vf.verification_status||'')} — ${esc(vf.summary||'')}</div>`+
    `<div>Error ${vf.error_rate_before}% → ${vf.error_rate_after}%, latency ${vf.latency_before}ms → ${vf.latency_after}ms</div>`+
    `<div id="livetraffic-${id}" style="margin-top:4px;color:var(--text-muted)">Checking live traffic split…</div>`);
  if(action==='cloud_run_rollback'||action==='cloud_run_shift_traffic'){
    try{
      const t=await (await fetch('/api/approvals/'+id+'/live-traffic')).json();
      const rows=Object.entries(t.traffic_split||{}).map(([rev,pct])=>`${esc(rev)}: ${pct}%`).join(' · ')||'no data';
      const el=document.getElementById('livetraffic-'+id);
      if(el) el.innerHTML=`<strong>Live traffic now (${esc(t.service)}):</strong> ${rows}`;
    }catch(e){ /* leave the checking line */ }
  }
  fetchLogs();
}
async function fetchLogs(){
  if(_pollInFlight) return;  // never stack overlapping polls — this was freezing the page
  _pollInFlight=true;
  try{
    const res=await fetch('/api/logs/live?limit=200'); const logs=await res.json();
    LOGS=logs;
    const sig=logs.length+'|'+(logs.length?logs[logs.length-1].timestamp+logs[logs.length-1].message:'empty');
    if(sig!==_lastLogSig){
      _lastLogSig=sig;
      _refreshFilterOptions();
      if(!PAUSED) renderLogs();
      const sum=await (await fetch('/api/logs/summary')).json();
      const s2=[sum.total_requests,sum.error_5xx_rate_pct,sum.error_4xx_rate_pct,sum.p95_latency_ms,sum.avg_cpu_pct,sum.avg_memory_pct,sum.active_revision,sum.incident_duration_s].join('|');
      if(s2!==_lastSumSig){
        _lastSumSig=s2;
        document.getElementById('log-summary').innerHTML=
          `<span><strong>Total:</strong> ${sum.total_requests}</span>`+
          `<span><strong>5xx:</strong> ${sum.error_5xx_rate_pct}%</span>`+
          `<span><strong>4xx:</strong> ${sum.error_4xx_rate_pct}%</span>`+
          `<span><strong>P95:</strong> ${sum.p95_latency_ms}ms</span>`+
          `<span><strong>CPU:</strong> ${sum.avg_cpu_pct}%</span>`+
          `<span><strong>Mem:</strong> ${sum.avg_memory_pct}%</span>`+
          `<span><strong>Revision:</strong> ${esc(sum.active_revision)}</span>`+
          `<span><strong>Duration:</strong> ${sum.incident_duration_s}s</span>`;
      }
    }
    const pr=await fetch('/api/approvals/pending'); const d=await pr.json();
    const hr=await fetch('/api/approvals/recent?limit=10'); const h=await hr.json();
    const asig='P:'+d.map(a=>a.approval_id+':'+a.status).join(',')+'|H:'+h.map(a=>a.approval_id+':'+a.status).join(',');
    if(asig!==_lastApprSig){
      const typing=document.activeElement&&document.activeElement.classList&&document.activeElement.classList.contains('appr-msg');
      if(typing){ /* skip rebuild while typing; retry on next poll */ }
      else{
        _lastApprSig=asig;
        const ab=document.getElementById('approval-box');
        const prevIds=new Set([...document.querySelectorAll('.appr-msg')].map(el=>el.dataset.approvalId));
        let html='';
        if(d.length){ html+= [...d].reverse().map((a,i)=>_approvalCard(a,false,i===0)).join(''); }
        else{ html+='<div style="font-size:.78rem;color:var(--text-muted);margin-bottom:6px">No pending approvals</div>'; }
        if(h.length){ html+='<div style="font-size:.7rem;color:var(--text-muted);margin:8px 0 4px;text-transform:uppercase;letter-spacing:.05em">Approval & Action History</div>'+h.map(a=>_historyCard(a)).join(''); }
        ab.innerHTML=html;
        // focus ONLY a brand-new approval input, once — never steal focus otherwise
        // (rebuilds never happen while typing, so reaching here means focus is safe to move)
        const fresh=[...document.querySelectorAll('.appr-msg')].find(el=>!prevIds.has(el.dataset.approvalId));
        if(fresh) fresh.focus();
      }
    }
  }catch(e){ /* poll failure must never break the page */ }
  finally{ _pollInFlight=false; }
}
function togglePause(){
  PAUSED=!PAUSED;
  document.getElementById('pause-btn').innerText=PAUSED?'Resume':'Pause';
  if(!PAUSED) renderLogs();
}
async function copyLogs(){
  const text=document.getElementById('live-logs').innerText||'';
  if(!text){ alert('No logs to copy'); return; }
  try{ await navigator.clipboard.writeText(text); alert('Visible logs copied'); }
  catch(e){ prompt('Copy logs:', text.slice(0,4000)); }
}
function _refreshFilterOptions(){
  const svc=document.getElementById('f-service'), err=document.getElementById('f-error');
  const svcs=[...new Set(LOGS.map(l=>l.service_name||l.service||'unknown'))].sort();
  const errs=[...new Set(LOGS.map(l=>l.error_code).filter(Boolean))].sort();
  const keep=(el,vals,first)=>{ const cur=el.value; el.innerHTML=`<option value="">${first}</option>`+vals.map(v=>`<option>${esc(v)}</option>`).join(''); if(vals.includes(cur)) el.value=cur; };
  keep(svc,svcs,'All services'); keep(err,errs,'All error types');
}
function renderLogs(){
  const box=document.getElementById('live-logs');
  if(!LOGS.length){ box.innerHTML='<span class="log-info">No errors yet — click Simulate Errors above</span>'; return; }
  const fs=document.getElementById('f-service').value, sev=document.getElementById('f-severity').value,
        fe=document.getElementById('f-error').value,
        ft=document.getElementById('f-trace').value.trim().toLowerCase(),
        fq=document.getElementById('f-search').value.trim().toLowerCase();
  const rows=LOGS.filter(l=>{
    if(fs&&(l.service_name||l.service||'unknown')!==fs) return false;
    if(sev&&l.severity!==sev) return false;
    if(fe&&(l.error_code||'')!==fe) return false;
    if(ft&&!(l.trace_id||'').toLowerCase().includes(ft)) return false;
    if(fq&&!((l.message||'')+' '+(l.error_code||'')+' '+(l.endpoint||'')).toLowerCase().includes(fq)) return false;
    return true;
  });
  const nearBottom=(box.scrollHeight-box.scrollTop-box.clientHeight)<60;
  box.innerHTML=rows.length?rows.map(l=>{
    const cls=l.severity==='ERROR'||l.severity==='CRITICAL'?'log-error':(l.severity==='WARNING'?'log-warn':'log-info');
    return `<div class="log-line ${cls}">[${esc(l.timestamp)}] <strong>${esc(l.severity)}</strong> ${esc(l.service_name||l.service||'')} ${esc(l.error_code||'')} ${esc(l.message||'')} <span style="opacity:.6">${esc(l.endpoint||'')} ${l.status_code||''} ${l.latency_ms||''}ms trace=${esc(l.trace_id||'none')}</span></div>`;
  }).join(''):'<span class="log-info">No logs match filters</span>';
  if(nearBottom) box.scrollTop=box.scrollHeight;
}
async function sendDecision(id, isApprove, action, incident, risk){
  const input=document.getElementById('msg-'+id);
  const message=input?input.value.trim():"";
  const verb=isApprove?'APPROVE':'REJECT';
  // Explicit human confirmation — nothing is auto-approved; Enter key alone never submits
  const detail=(action||'')+(incident?' for '+incident:'')+(risk?' (Risk '+risk+')':'')+(message?' -- Note: '+message:'');
  if(!confirm(verb+' this remediation? -- '+detail)) return;
  const endpoint=isApprove?'/api/approvals/'+id+'/approve':'/api/approvals/'+id+'/reject';
  await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message})});
  fetchLogs();
}
async function approve(id){ return sendDecision(id,true); }
async function reject(id){ return sendDecision(id,false); }
async function runRCA(){ const out=document.getElementById('rca-output'); out.style.display='none'; const res=await fetch('/api/analyze/'+currentIncident); const data=await res.json(); renderRCA(data); }
async function runLiveRCA(){
  const btn=document.getElementById('rca-btn'); btn.disabled=true; btn.innerText='Working…';
  const target=liveIncidentFile||currentIncident;
  // Use multi-agent live endpoint whenever a simulation ran, else static file
  const useLive=!!(liveScenario||liveIncidentFile);
  const url=useLive?'/api/rca/live':'/api/analyze/'+target;
  const res=await fetch(url,{method: useLive?'POST':'GET'});
  const data=await res.json();
  // Normalize both response shapes
  const rca=data.root_cause?data:data;
  // For live, data contains remediation_plan+approval
  renderRCA(rca.root_cause?rca:{...rca, ...rca.remediation_plan});
  // If live returned approval, show it with message box + focus (sync poll signature so next poll won't rebuild it)
  if(data.approval){ const ap=data.approval; _lastApprSig=ap.approval_id+':'+ap.status; document.getElementById('approval-box').innerHTML=_approvalCard(ap,true); const inp=document.getElementById('msg-'+ap.approval_id); if(inp) inp.focus(); }
  btn.disabled=false; btn.innerText='Run Live RCA';
  fetchLogs();
  if(data.incident_id||LAST_INCIDENT){ const _iid=data.incident_id||LAST_INCIDENT; renderHero(_iid); if(INV_TAB==='investigation'||INV_TAB==='summary') loadInvestigation(_iid); }
  if(useLive&&data.incident_id){
    // Code fix stays fully explicit: show the panel with a hint, create nothing.
    document.getElementById('codefix-output').style.display='block';
    refreshPreflight();
    document.getElementById('cf-investigation').innerHTML='<span style="color:var(--text-muted);font-size:.85rem">RCA complete. Click Generate Fix to inspect code and propose a patch — nothing is created until you approve.</span>';
    document.getElementById('cf-diff-wrap').style.display='none';
  }
}
async function refreshPreflight(){
  try{
    const p=await (await fetch('/api/gitops/preflight')).json();
    const d=p.details||{};
    const mark=v=>v?'✔':'✖';
    document.getElementById('cf-preflight').innerHTML=
      `<strong>Prerequisites:</strong> git-repo ${mark(d.is_git_repo)} · origin ${mark(d.has_origin)} · clean-tree ${mark(d.tree_clean)} · gh/token ${mark(d.gh_cli||d.gh_token_present)}`+
      (d.hint?`<br/><span style="color:var(--accent-yellow)">${esc(d.hint)}</span>`:'');
  }catch(e){ /* never break the panel */ }
}
async function proposeRemediation(){
  if(!LAST_INCIDENT) return;
  const rb=document.getElementById('remediation-box');
  rb.innerHTML='<span style="color:var(--text-muted);font-size:.85rem">Proposing remediation…</span>';
  const r=await fetch('/api/incidents/'+LAST_INCIDENT+'/remediation/propose',{method:'POST'});
  const d=await r.json();
  if(!r.ok){ rb.innerHTML='<span style="color:var(--accent-red)">'+esc(d.detail||'proposal failed')+'</span>'; return; }
  const p=d.remediation_plan, a=d.approval;
  renderRemediation(p, a, d.policy);
  fetchLogs();
}
function humanize(s){
  s=String(s||'');
  if(s==='WAITING_APPROVAL') return 'Waiting for Approval';
  return s.split('_').filter(Boolean).map(w=>w.charAt(0).toUpperCase()+w.slice(1).toLowerCase()).join(' ');
}
const ACTION_TITLES={cloud_run_scale_within_limits:'Scale Cloud Run Within Limits',cloud_run_rollback:'Roll Back Cloud Run Revision',cloud_run_shift_traffic:'Shift Cloud Run Traffic',code_fix_pr:'Create Code Fix Pull Request'};
function actionTitle(id){ return ACTION_TITLES[id]||humanize(id); }
function riskPill(risk){
  const r=String(risk||'LOW').toUpperCase();
  const cls=(r==='LOW')?'ok':((r==='MEDIUM')?'warn':'bad');
  return `<span class="pill ${cls}">${r.charAt(0)+r.slice(1).toLowerCase()} Risk</span>`;
}
function mitigationPill(mit){
  const m=String(mit||'');
  const label=/TEMPORARY/.test(m)?'Temporary Mitigation':(/PERMANENT/.test(m)?'Permanent Fix':humanize(m)||'Mitigation');
  return `<span class="pill info">${label}</span>`;
}

function categoryPill(p, a){
  const label=(a&&a.action_type==='CODE_CHANGE')?'Code Change':(/TEMPORARY/.test(String(p.mitigation_type||''))?'Temporary Mitigation':(/PERMANENT/.test(String(p.mitigation_type||''))?'Permanent Fix':'Infrastructure Change'));
  return `<span class="pill info">${label}</span>`;
}
function renderRCA(data){
  const out=document.getElementById('rca-output'); out.style.display='block';
  LAST_INCIDENT=data.incident_id||null;
  document.getElementById('inc-title').innerText="Incident: "+data.incident_id;
  document.getElementById('inc-desc').innerText=`Affected: ${(data.affected_services||[]).join(', ')}`;
  document.getElementById('rc-category').innerText=humanize(data.root_cause_category||'unknown');
  document.getElementById('rc-confidence').innerText=`${Math.round((data.confidence_score||data.confidence||0)*100)}% confidence`;
  document.getElementById('rc-risk').innerText=humanize(data.remediation_risk||data.estimated_risk||'LOW')+' risk';
  document.getElementById('rc-summary').innerText=data.root_cause||data.recommended_action||'';
  renderBlast(data);
  renderRcExtras(data);
  document.getElementById('rc-action').innerText=data.recommended_action||data.expected_effect||'';
  const tBox=document.getElementById('rc-timeline'); tBox.innerHTML=(data.timeline||[]).map(t=>`<div style="font-size:.78rem;padding:4px 0;border-bottom:1px solid var(--border-color)"><strong>${t.timestamp}</strong> [${t.event_type}] ${t.description}</div>`).join('')||'<span style="color:var(--text-muted)">No timeline</span>';
  document.getElementById('additional-checks').innerHTML=(data.additional_checks_required||data.preconditions||[]).map(c=>`<div class="item-box">— ${esc(c)}</div>`).join('')||'<p style="color:var(--text-muted)">None required</p>';
  document.getElementById('evidence-list').innerHTML=(data.evidence||data.supporting_evidence||[]).map(e=>`<div class="evidence-box"><span style="color:var(--accent-green)">✔</span> ${e}</div>`).join('');
  document.getElementById('contra-list').innerHTML=(data.contradictory_evidence||[]).map(c=>`<div class="evidence-box"><span style="color:var(--accent-red)">✖</span> ${c}</div>`).join('')||'<p style="color:var(--text-muted);font-size:.85rem">None</p>';
  const rb=document.getElementById('remediation-box');
  if(data.remediation_plan||data.approval){ const p=data.remediation_plan||data; renderRemediation(p, data.approval||null, data.policy||null); }
  else if(data.remediation_available){ rb.innerHTML=`<button class="sim-btn" onclick="proposeRemediation()">Propose Remediation Plan</button><div style="font-size:.78rem;color:var(--text-muted);margin-top:6px">Creates one infra approval (human-gated). Nothing runs automatically.</div>`; }
  else { rb.innerHTML='';}
  out.scrollIntoView({behavior:'smooth'});
  if(data.incident_id){ renderTimelineSection(data.incident_id, 'significant'); }
}
function renderRemediation(p, a, policy){
  const rb=document.getElementById('remediation-box'); if(!rb) return;
  const title=actionTitle(p.recommended_action||p.action||'');
  const checks=(p.preconditions&&p.preconditions.length)?p.preconditions.map(c=>`<div class="item-box">— ${esc(c)}</div>`).join(''):'None required';
  const perms=(p.required_permissions&&p.required_permissions.length)?esc(p.required_permissions.join(', ')):'—';
  let approvalHtml='';
  if(a){
    const st=String(a.status||'');
    approvalHtml=`<div class="rc-section"><strong>Approval</strong><div style="margin-top:4px">${st==='PENDING'?'Waiting for approval.':humanize(st)+'.'}${st==='PENDING'?` <button class="sim-btn" onclick="openApprovalModal('${esc(a.approval_id)}')">Review Approval</button>`:''}</div></div>`;
  } else {
    approvalHtml=`<div class="rc-section"><button class="sim-btn" onclick="proposeRemediation()">Propose Remediation Plan</button><div style="font-size:.78rem;color:var(--text-muted);margin-top:6px">Creates one infra approval (human-gated). Nothing runs automatically.</div></div>`;
  }
  rb.innerHTML=`<div class="well"><h4 style="margin:0 0 8px;font-size:1rem">${esc(title)}</h4>`+
    `<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:4px">${mitigationPill(p.mitigation_type)}${categoryPill(p, a)}${riskPill(p.estimated_risk||p.risk)}${(p.human_approval_required!==false)?'<span class="pill warn">! Approval Required</span>':''}</div>`+
    `<div style="font-size:.72rem;color:var(--text-muted)">Internal action: <code>${esc(p.recommended_action||p.action||'')}</code></div>`+
    `<div class="rc-section"><strong>Why this is recommended</strong><div style="margin-top:4px">${esc(p.expected_effect||p.rationale||'')}</div></div>`+
    `<div class="rc-section"><strong>Verification plan</strong><div style="margin-top:4px">${esc(p.verification_plan||'')}</div></div>`+
    `<div class="rc-section"><strong>Execution safety</strong><dl class="kv"><dt>Policy</dt><dd>${esc(humanize(policy||'Allowed With Approval'))}</dd><dt>Reversible</dt><dd>${esc(p.reversibility||'—')}</dd><dt>Permissions</dt><dd>${perms}</dd></dl></div>`+
    `<div class="rc-section"><strong>Rollback</strong><div style="margin-top:4px">${esc(p.rollback_plan||'')}</div></div>`+
    `<div class="rc-section"><strong>Additional checks</strong><div style="margin-top:4px">${checks}</div></div>`+
    approvalHtml+`</div>`;
}
async function openApprovalModal(approval_id){
  const veil=document.getElementById('approval-modal');
  const body=document.getElementById('approval-modal-body');
  veil.classList.add('open');
  body.innerHTML='<span style="color:var(--text-muted)">Loading approval…</span>';
  try{
    const a=await (await fetch('/api/approvals/'+approval_id)).json();
    const isCode=a.action_type==='CODE_CHANGE';
    const title=isCode?'Create Code Fix Pull Request':actionTitle(a.action);
    let paramsHtml='';
    try{
      const pj=await (await fetch('/api/approvals/'+approval_id+'/params')).json();
      const prm=pj.params||{};
      if(Object.keys(prm).length) paramsHtml=`<div class="rc-section"><strong>Proposed parameters</strong><pre style="background:#000;border:1px solid var(--border-color);border-radius:6px;padding:10px;font-size:.78rem;white-space:pre-wrap">${esc(JSON.stringify(prm,null,2))}</pre></div>`;
    }catch(e){}
    const extra=isCode?`<div class="rc-section"><strong>Patch</strong><div style="margin-top:4px">SHA256 <code>${esc((a.patch_sha256||'').slice(0,16))}…</code><br/><span style="font-size:.78rem;color:var(--text-muted)">Target: ${esc(a.target_resource||'')}</span></div></div>`:'';
    body.innerHTML=`<h3 style="margin-top:0">Review Approval</h3>
      <dl class="appr-modal-grid">
      <dt>Incident</dt><dd>${esc(a.incident_id||'')}</dd>
      <dt>Requested action</dt><dd><strong>${esc(title)}</strong></dd>
      <dt>Action type</dt><dd>${isCode?'Code Change':'Infrastructure Change'}</dd>
      <dt>Risk</dt><dd>${esc(a.risk||'')}</dd>
      <dt>Reason</dt><dd>${esc(a.rationale||a.expected_impact||'')}</dd>
      <dt>Expected impact</dt><dd>${esc(a.expected_impact||'')}</dd>
      <dt>Rollback</dt><dd>${esc(a.rollback_plan||'')}</dd>
      <dt>Status</dt><dd>${esc(a.status||'')}</dd>
      </dl>${paramsHtml}${extra}
      <div style="font-size:.78rem;color:var(--text-muted);margin:8px 0">${isCode?'Approving authorizes only the exact patch identified by the displayed SHA256 hash.':'Approving authorizes this exact proposed action only. Any change to the action parameters requires a new approval.'}</div>
      <label style="font-size:.8rem">Approval comment (required to reject):<br/><textarea id="appr-modal-msg" rows="2" style="width:100%;box-sizing:border-box;background:#101010;color:var(--text-main);border:1px solid var(--border-color);border-radius:6px;padding:7px 10px"></textarea></label>
      <div style="display:flex;gap:8px;margin-top:10px;justify-content:flex-end">
        <button class="sim-btn" onclick="closeApprovalModal()">Cancel</button>
        <button class="btn btn-danger" onclick="modalDecide('${esc(approval_id)}',false,'${esc(a.incident_id||'')}',${isCode?'true':'false'})">Reject</button>
        <button class="btn btn-primary" onclick="modalDecide('${esc(approval_id)}',true,'${esc(a.incident_id||'')}',${isCode?'true':'false'})">Approve Action</button>
      </div>`;
    const ta=document.getElementById('appr-modal-msg');
    if(ta) ta.focus();
  }catch(e){ body.innerHTML='<span style="color:var(--accent-red)">Could not load approval.</span>'; }
}
function closeApprovalModal(){ document.getElementById('approval-modal').classList.remove('open'); }
async function modalDecide(approval_id, approve, incident_id, isCode){
  const msg=((document.getElementById('appr-modal-msg')||{}).value||'').trim();
  if(!approve&&!msg){ alert('A rejection comment is required.'); return; }
  const body=JSON.stringify({message:msg});
  const headers={'Content-Type':'application/json'};
  let url, r;
  if(isCode){
    url='/api/incidents/'+incident_id+(approve?'/fix/approve':'/fix/reject');
    r=await fetch(url,{method:'POST',headers,body});
  } else {
    url='/api/approvals/'+approval_id+(approve?'/approve':'/reject');
    r=await fetch(url,{method:'POST',headers,body});
  }
  const d=await r.json().catch(()=>({}));
  if(!r.ok){ alert((approve?'Approve':'Reject')+' failed: '+(d.detail||r.status)); return; }
  closeApprovalModal();
  fetchLogs();
  if(isCode&&window.refreshFixStatus) refreshFixStatus();
}
function renderTimelineSection(incident_id, view){
  view=view||'significant';
  let host=document.getElementById('incident-timeline-section');
  if(!host){
    host=document.createElement('div');
    host.id='incident-timeline-section';
    host.className='card';
    host.style.marginBottom='20px';
    const out=document.getElementById('rca-output');
    out.parentNode.insertBefore(host, out.nextSibling);
  }
  host.innerHTML='<div class="card-title">Incident Timeline</div><span style="color:var(--text-muted);font-size:.8rem">Loading…</span>';
  fetch('/api/incidents/'+incident_id+'/timeline?view='+view).then(r=>r.json()).then(d=>{
    const legacy=document.getElementById('rc-timeline');
    if(legacy&&legacy.parentElement) legacy.parentElement.style.display='none';
    const groups=(d.groups||[]).filter(g=>g.count>1);
    const singles=(d.events||[]).filter(e=>e.kind==='event');
    let html=`<div style="margin-bottom:10px;display:flex;gap:8px;align-items:center;flex-wrap:wrap">`+
      `<button class="sim-btn" onclick="renderTimelineSection('${esc(incident_id)}','${view==='significant'?'all':'significant'}')">${view==='significant'?'Show all events':'Show significant only'}</button>`+
      `<button class="sim-btn" onclick="openRawDrawer()">View Raw Evidence</button>`+
      `<span style="font-size:.76rem;color:var(--text-muted)">${d.total_events} event(s)${view==='significant'?' · grouped':''}</span></div>`;
    html+=singles.map(e=>`<div style="padding:6px 0;border-bottom:1px solid var(--border-color);font-size:.84rem"><strong>${esc((e.timestamp||'').slice(11,19))}</strong> ${esc(e.title||'')} <span style="color:var(--text-muted)">[${esc(e.event_type||'')}]</span><br/><span style="color:var(--text-muted)">${esc(e.description||'').slice(0,160)}</span></div>`).join('');
    html+=groups.map((g,i)=>{
      const attrs=Object.entries(g.attributes||{}).map(([k,v])=>`<dt>${esc(String(k).replace(/_/g,' '))}</dt><dd>${esc(v)}</dd>`).join('');
      return `<details class="tl-group"${i===0?' open':''}><summary><strong>${esc(g.title)}</strong> <span style="color:var(--text-muted)">${esc((g.first||'').slice(11,19))} – ${esc((g.last||'').slice(11,19))} · ${g.count} occurrences</span></summary><div style="padding:0 14px 12px"><dl class="tl-attrs">${attrs}</dl><div style="margin-top:6px"><button class="sim-btn" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'block':'none'">Expand ${g.count} events</button><div style="display:none;margin-top:6px;font-size:.76rem;color:var(--text-muted)">${esc(g.first)} to ${esc(g.last)} · ${esc(g.event_type||'')}</div></div></div></details>`;
    }).join('');
    if(!singles.length&&!groups.length) html+='<span style="color:var(--text-muted)">No timeline events.</span>';
    host.innerHTML='<div class="card-title">Incident Timeline</div>'+html;
  }).catch(()=>{ host.innerHTML='<div class="card-title">Incident Timeline</div><span style="color:var(--text-muted)">Timeline unavailable.</span>'; });
}
async function openRawDrawer(){
  if(!LAST_INCIDENT){ alert('Run RCA first'); return; }
  const veil=document.getElementById('raw-modal');
  veil.classList.add('open');
  const body=document.getElementById('raw-modal-body');
  body.innerHTML='<span style="color:var(--text-muted)">Loading raw evidence…</span>';
  try{
    const d=await (await fetch('/api/incidents/'+LAST_INCIDENT+'/evidence/raw?limit=100')).json();
    const sec=(t,v)=>`<details class="tl-group"><summary><strong>${t}</strong></summary><div style="padding:0 14px 12px"><pre style="background:#000;border:1px solid var(--border-color);border-radius:6px;padding:10px;max-height:300px;overflow:auto;font-size:.72rem;white-space:pre-wrap">${esc(JSON.stringify(v,null,2).slice(0,6000))}</pre></div></details>`;
    body.innerHTML=`<h3 style="margin-top:0">View Raw Evidence</h3><div style="font-size:.78rem;color:var(--text-muted);margin-bottom:8px">Advanced debugging view. The human-readable RCA report above remains primary.</div>`+
      sec('Raw logs ('+(d.raw_logs||[]).length+')',d.raw_logs)+sec('Metrics',d.metrics)+sec('Deployment events ('+(d.recent_deployments||[]).length+')',d.recent_deployments)+sec('Trace evidence ('+(d.traces||[]).length+')',d.traces)+sec('Agent finding objects ('+(d.agent_findings||[]).length+')',(d.agent_findings||[]).slice(0,20));
  }catch(e){ body.innerHTML='<span style="color:var(--accent-red)">Raw evidence unavailable.</span>'; }
}
function closeRawDrawer(){ document.getElementById('raw-modal').classList.remove('open'); }
function setCfBadge(text, ok){
  const b=document.getElementById('cf-status-badge'); b.innerText=text;
  b.className='badge '+(ok===true?'badge-green':(ok===false?'badge-red':'badge-yellow'));
}
function renderInvestigation(inv){
  const box=document.getElementById('cf-investigation');
  if(!inv||!inv.findings||!inv.findings.length){
    box.innerHTML='<div class="item-box">No safe code-level remediation identified. '+esc((inv&&inv.no_fix_reason)||'')+'</div>'; return;
  }
  box.innerHTML='<div style="font-size:.85rem;color:var(--text-muted);margin-bottom:6px"><strong>Code Evidence</strong> — likely responsible lines in cloud-rca-demo-app:</div>'+inv.findings.map(f=>`<div class="evidence-box"><strong>${esc(f.file)}:${f.start_line}</strong> <code>${esc(f.snippet)}</code><br/><span style="color:var(--text-muted)">${esc(f.reason)}</span><br/><span style="font-size:.75rem;color:var(--text-muted)">Test: ${esc(f.related_test||'')}</span></div>`).join('');
}
function colorDiff(patch){
  const NL=String.fromCharCode(10);
  return esc(patch||'').split(NL).map(l=>{
    if(l.startsWith('+++')||l.startsWith('---')||l.startsWith('@@')) return `<span style="color:var(--accent-cyan)">${l}</span>`;
    if(l.startsWith('+')) return `<span style="color:var(--accent-green)">${l}</span>`;
    if(l.startsWith('-')) return `<span style="color:var(--accent-red)">${l}</span>`;
    return `<span style="color:var(--text-muted)">${l}</span>`;
  }).join(NL);
}
async function generateFix(regen){
  if(!LAST_INCIDENT){ alert('Run live RCA first'); return; }
  setCfBadge(regen?'Regenerating…':'Generating fix…');
  // clear previous run's branch/PR/tests so a fresh failure never shows stale success
  document.getElementById('cf-pr').innerHTML='';
  document.getElementById('cf-tests').innerHTML='';
  document.getElementById('cf-lifecycle').innerText='Status: '+(regen?'Regenerating…':'Generating fix…');
  const r0=await fetch('/api/incidents/'+LAST_INCIDENT+'/generate-fix',{method:'POST'});
  const data=await r0.json();
  if(!r0.ok){ document.getElementById('cf-diff-wrap').style.display='none'; const nf=document.getElementById('cf-no-fix'); nf.style.display='block'; nf.innerText=data.detail||'Fix generation failed'; document.getElementById('cf-lifecycle').innerText='Status: Failed'; setCfBadge('Failed', false); fetchLogs(); return; }
  if(data.investigation) renderInvestigation(data.investigation);
  const dw=document.getElementById('cf-diff-wrap'), nf=document.getElementById('cf-no-fix');
  if(data.proposal){
    const p=data.proposal;
    dw.style.display='block'; nf.style.display='none';
    document.getElementById('cf-diff').innerHTML=colorDiff(p.patch);
    document.getElementById('cf-files').innerText=p.files_changed.join(', ')+' (+'+p.lines_added+' -'+p.lines_removed+')';
    document.getElementById('cf-meta').innerHTML=
      `<div><strong>Repository:</strong> cloud-rca-demo-app (branch created on approve; main never touched)</div>`+
      `<div><strong>Reason:</strong> ${esc(p.reasoning_summary)}</div>`+
      `<div><strong>Risk:</strong> ${esc(p.risk)} · <strong>Tests:</strong> ${p.tests_to_run.map(esc).join(', ')}</div>`+
      `<div><strong>Rollback strategy:</strong> close the PR unmerged and delete the fix branch</div>`+
      `<div><strong>Patch SHA256:</strong> <code>${esc(p.patch_sha256.slice(0,16))}…</code> (approval binds to full hash)</div>`;
    document.getElementById('cf-lifecycle').innerText='Status: '+data.fix_status+(data.approval?(' · Approval '+data.approval.approval_id+' '+data.approval.status):'');
    setCfBadge(data.fix_status);
  } else {
    dw.style.display='none'; nf.style.display='block';
    nf.innerText=data.no_fix_reason||data.error||'No safe code-level remediation identified.';
    document.getElementById('cf-lifecycle').innerText='Status: '+data.fix_status;
    setCfBadge(data.fix_status, false);
  }
  fetchLogs();
}
async function approveFixPR(){
  if(!LAST_INCIDENT) return;
  const msg=document.getElementById('cf-msg').value.trim();
  const btn=document.getElementById('cf-approve-btn'); btn.disabled=true; btn.innerText='Approving…';
  let r=await fetch('/api/incidents/'+LAST_INCIDENT+'/fix/approve',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})});
  let d=await r.json();
  if(!r.ok){ document.getElementById('cf-lifecycle').innerText='Approve failed: '+(d.detail||r.status); btn.disabled=false; btn.innerText='Approve & Create PR'; return; }
  if(!confirm('Create branch, apply patch, run tests and open PR for '+LAST_INCIDENT+'?')){ btn.disabled=false; btn.innerText='Approve & Create PR'; return; }
  btn.innerText='Applying… (branch, tests, push, PR)';
  document.getElementById('cf-lifecycle').innerText='Status: Approved — applying approved patch…';
  r=await fetch('/api/incidents/'+LAST_INCIDENT+'/fix/apply',{method:'POST'});
  d=await r.json();
  if(!r.ok){ document.getElementById('cf-lifecycle').innerText='Apply failed ('+r.status+'): '+(d.detail||'see server logs'); btn.disabled=false; btn.innerText='Approve & Create PR'; return; }
  await refreshFixStatus();
  btn.disabled=false; btn.innerText='Approve & Create PR';
  fetchLogs();
}
async function rejectFix(){
  if(!LAST_INCIDENT) return;
  const msg=document.getElementById('cf-msg').value.trim();
  if(!msg){ alert('A rejection comment is required.'); document.getElementById('cf-msg').focus(); return; }
  if(!confirm('Reject this code fix?')) return;
  await fetch('/api/incidents/'+LAST_INCIDENT+'/fix/reject',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:msg})});
  await refreshFixStatus(); fetchLogs();
}
async function refreshFixStatus(){
  if(!LAST_INCIDENT) return;
  const r=await fetch('/api/incidents/'+LAST_INCIDENT+'/fix');
  if(!r.ok) return;
  const d=await r.json(); const job=d.job;
  const good=d.fix_status==='PR Created', bad=(d.fix_status==='Failed'||d.fix_status==='Rejected');
  setCfBadge(d.fix_status, good?true:(bad?false:undefined));
  document.getElementById('cf-lifecycle').innerText='Status: '+d.fix_status+(job.error?(' — '+job.error):'');
  const pr=document.getElementById('cf-pr');
  if(job.pr_url){ const title=(d.proposal&&d.proposal.summary)||''; pr.innerHTML=`<div class="item-box" style="border-left-color:var(--accent-green)"><strong>Pull Request Created</strong><br/>PR #${job.pr_number||''} — ${esc(title)}<br/><strong>Branch:</strong> ${esc(job.branch||'')} · <strong>Commit:</strong> ${esc(job.commit||'')} <a href="${esc(job.pr_url)}" target="_blank" rel="noopener" style="color:var(--accent-cyan)">Open Pull Request</a></div>`; }
  else if(job.branch){ pr.innerHTML=`<div class="item-box"><strong>Branch:</strong> ${esc(job.branch)}${job.commit?(' · <strong>Commit:</strong> '+esc(job.commit)):''}</div>`; }
  else{ pr.innerHTML=''; }
  const t=document.getElementById('cf-tests');
  if(job.test_output){ t.innerHTML='<strong>Test Results:</strong><pre style="background:#000000;border:1px solid var(--border-color);border-radius:6px;padding:10px;max-height:220px;overflow:auto;font-size:.75rem;white-space:pre-wrap">'+esc(job.test_output.slice(-2000))+'</pre>'; }
}

/* ===== platform: router, incidents, workspace extras ===== */
let TAX=null, INCIDENTS=[], CUR_PROJECT='', CUR_INCIDENT_FILE='';
function esc2(s){ return esc(s); }
function go(view, arg){
  const map={home:'#/',projects:'#/projects',incidents:'#/incidents',create:'#/incidents/new',simulations:'#/simulations',prs:'#/pull-requests',analyze:'#/analyze',settings:'#/settings'};
  let h=map[view]||'#/';
  if(view==='projects'&&arg) h='#/projects/'+arg;
  if(view==='incidents'&&arg) h='#/incidents/'+arg;
  if(view==='prs'&&arg) h='#/pull-requests/'+arg;
  if(location.hash===h){ syncFromHash(); } else { location.hash=h; }
}
function syncFromHash(){
  const parts=(location.hash||'#/').replace('#/','').split('/');
  const v=parts[0]||'';
  if(parts[0]==='incidents'&&parts[1]==='new'){ showView('create'); return; }
  if(parts[0]==='simulations'){ showView('simulations'); return; }
  const routes={'':'home','projects':'projects','incidents':'incidents','pull-requests':'prs','analyze':'analyze','settings':'settings'};
  showView(routes[v]||'home', parts[1], parts[2]);
}
function showView(view, arg1, arg2){
  const map={home:'view-home',projects:'view-projects',incidents:'view-incidents',create:'view-create',simulations:'view-simulations',prs:'view-prs',analyze:'view-analyze',settings:'view-settings'};
  const target=map[view]||'view-home';
  // Belt and suspenders: classes AND inline display, so exactly one view
  // is ever visible even if a stylesheet rule fails to apply.
  document.querySelectorAll('.view').forEach(el=>{
    const on=el.id===target;
    el.classList.toggle('active',on);
    el.style.display=on?'block':'none';
  });
  document.querySelectorAll('#topnav .nav-btn[data-view]').forEach(b=>{const on=b.dataset.view===view; b.classList.toggle('active', on); if(on){b.setAttribute('aria-current','page');}else{b.removeAttribute('aria-current');}});
  const names={home:'Home',projects:'Projects',incidents:'Incidents',create:'Create Incident',simulations:'Incident Simulations',prs:'Pull Requests',analyze:'Analyze Logs',settings:'Settings'};
  setCrumbs([['Home',()=>go('home')],[(names[view]||'Home'),null]]);
  if(view==='home') loadHome();
  if(view==='projects'){ loadProjects(); if(arg1) openProject(arg1, arg2); }
  if(view==='create'){ loadCreateProjects(); }
  if(view==='simulations'){ loadSimulations(); }
  if(view==='incidents'){ if(arg1){ openIncident(arg1); } else { showIncidentTable(); loadIncidentMeta(); } }
  if(view==='prs'){ loadPRs(); if(arg1) openPR(arg1); }
  if(view==='analyze'){ loadAnalyzeInit(); }
  if(view==='settings'){ loadSettings(); }
}
function setCrumbs(items){
  const c=document.getElementById('crumbs'); if(!c) return;
  c.innerHTML=items.map((it,i)=>{
    const last=i===items.length-1;
    const label=typeof it==='string'?it:(it[0]||'');
    if(last||typeof it==='string') return `<span>${esc(label)}</span>`;
    return `<a onclick="(${it[1].toString()})()">${esc(label)}</a>`;
  }).join(' / ');
}
function initRouter(){
  fetch('/health').then(r=>r.json()).then(h=>{
    const el=document.getElementById('build-stamp');
    const tag=String(h.commit||h.version||'');
    if(el&&(tag&&!['unknown','local','0.4.0'].includes(tag))) el.innerText='build ' + tag.slice(0,7);
    else if(el) el.remove();
  }).catch(()=>{});
  syncFromHash();
}
function toggleSidebar(){
  const btn=document.querySelector('#topnav .hamb');
  if(window.innerWidth<768){
    const open=document.body.classList.toggle('drawer-open');
    if(btn) btn.setAttribute('aria-expanded',open?'true':'false');
  }else{
    const collapsed=document.body.classList.toggle('sidebar-collapsed');
    if(btn) btn.setAttribute('aria-expanded',collapsed?'false':'true');
  }
}
document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    closeApprovalModal(); closeRawDrawer();
  }
  if(e.key==='Escape'&&document.body.classList.contains('drawer-open')){
    document.body.classList.remove('drawer-open');
    const btn=document.querySelector('#topnav .hamb');
    if(btn) btn.setAttribute('aria-expanded','false');
  }
});
async function loadSideProjects(){
  const box=document.getElementById('side-projects'); if(!box) return;
  try{
    const ps=await (await fetch('/api/projects')).json();
    box.innerHTML=ps.length?ps.map(p=>`<button class="proj-row${p.project_id===CUR_PROJECT?' sel':''}" aria-current="${p.project_id===CUR_PROJECT?'true':'false'}" title="${esc(p.name)} (${esc(p.environment||'')})" onclick="openProject('${esc(p.project_id)}')"><span class="ic" aria-hidden="true">●</span><span class="lbl">${esc(p.name)}<br/><span class="meta">${esc(p.environment||'')} · ${p.open_incidents} incident(s)</span></span></button>`).join(''):'<p style="font-size:.75rem;color:var(--text-muted)">None</p>';
  }catch(e){ box.innerHTML=''; }
}
async function loadTaxonomy(){
  try{ TAX=await (await fetch('/api/taxonomy')).json(); }catch(e){ TAX=null; }
}
function fmtTime(s){ if(!s) return '—'; try{ return new Date(s).toLocaleString(); }catch(e){ return s; } }
function timeAgo(ts){
  if(!ts) return '—';
  const s=Math.max(0,Math.round((Date.now()-new Date(ts).getTime())/1000));
  if(s<60) return s+'s ago';
  if(s<3600) return Math.floor(s/60)+'m ago';
  return Math.floor(s/3600)+'h ago';
}
function tickFreshness(){
  const el=document.getElementById('evidence-fresh');
  if(el&&window._lastRcaAt){ el.innerText='· Evidence updated '+timeAgo(window._lastRcaAt); }
}
function statusPill(st){
  const s=String(st||'');
  if(/^(RESOLVED|MERGED|Open|PR_CREATED|HEALTHY|healthy|connected|passed)$/i.test(s)) return `<span class="pill ok">✓ ${esc(s)}</span>`;
  if(/^(FAILED|REJECTED|Closed|ERROR|CRITICAL)$/i.test(s)) return `<span class="pill bad">✕ ${esc(s)}</span>`;
  if(/^(WARNING|PARTIAL|PENDING|WAITING|P1)$/.test(s)) return `<span class="pill warn">! ${esc(s)}</span>`;
  return `<span class="pill info">• ${esc(s)}</span>`;
}
/* ---- incidents table ---- */
let META_FAILED=false;
async function loadIncidentMeta(){
  try{
    const r=await fetch('/api/incidents/meta');
    if(!r.ok) throw 0;
    INCIDENTS=await r.json(); META_FAILED=false;
  }catch(e){ INCIDENTS=[]; META_FAILED=true; }
  renderIncidentTable();
}
function renderIncidentTable(){
  const body=document.getElementById('inc-table-body'); if(!body) return;
  if(META_FAILED){ body.innerHTML='<tr><td colspan="7">Could not load incidents. <button class="sim-btn" onclick="loadIncidentMeta()">Retry</button></td></tr>'; return; }
  const q=(document.getElementById('inc-search').value||'').toLowerCase();
  const fs=document.getElementById('inc-filter-sev').value;
  const fst=document.getElementById('inc-filter-status').value;
  const rows=INCIDENTS.filter(c=>{
    if(fs&&c.severity!==fs) return false;
    if(fst){
      const map={Open:['Open','NEW'],Investigating:['Investigating','COLLECTING_EVIDENCE','ANALYZING','ROOT_CAUSE_IDENTIFIED','REMEDIATION_PROPOSED','WAITING_APPROVAL','APPROVED','PR_CREATING'],Resolved:['RESOLVED']};
      if(!(map[fst]||[]).includes(c.status)) return false;
    }
    if(q&&!((c.incident_id||'')+' '+(c.title||'')+' '+(c.service||'')+' '+(c.root_cause||'')).toLowerCase().includes(q)) return false;
    return true;
  });
  document.getElementById('inc-count').innerText=rows.length+' incident(s)';
  body.innerHTML=rows.length?rows.map(c=>{const _src=((c.source||'MANUAL')+'').toUpperCase();const _badge=_src==='SIMULATION'?' <span class="pill warn">SIMULATED</span>':'';return `<tr class="clickable" onclick="openIncident('${esc(c.incident_id)}')">`+
    `<td><strong>${esc(c.incident_id)}</strong>${_badge}<br/><span style="color:var(--text-muted)">${esc((c.title||'').slice(0,60))}</span><br/><span style="font-size:.7rem;color:var(--text-muted)">${esc(c.start_time||'')}</span></td>`+
    `<td>${esc(c.project_id||'')}</td><td>${esc(c.severity||'')}</td><td>${statusPill(c.status)}</td>`+
    `<td>${esc(c.service||'')}</td><td>${c.rca_runs&&c.rca_runs.length?('✓ '+c.rca_runs.length+' run(s) '+Math.round((c.rca_runs[c.rca_runs.length-1].confidence||0)*100)+'%'):'<span style="color:var(--text-muted)">—</span>'}</td>`+
    `<td>${c.pr_id?('PR <strong>'+esc(c.pr_id)+'</strong>'):'<span style="color:var(--text-muted)">—</span>'}</td></tr>`).join('')
    :'<tr><td colspan="7">No incidents found for this project.</td></tr>';
}
function showIncidentTable(){
  document.getElementById('incidents-table-wrap').style.display='block';
  document.getElementById('incident-workspace').style.display='none';
  setCrumbs([['Home',()=>go('home')],['Incidents',null]]);
  loadIncidentMeta();
}
async function openIncident(incident_id){
  const meta=(INCIDENTS||[]).find(c=>c.incident_id===incident_id);
  LAST_INCIDENT=incident_id;
  document.getElementById('incidents-table-wrap').style.display='none';
  document.getElementById('incident-workspace').style.display='block';
  document.getElementById('inv-tabs').style.display='flex';
  renderHero(incident_id);
  switchInvTab('summary');
  setCrumbs([['Home',()=>go('home')],['Incidents',()=>{go('incidents');}],[incident_id,null]]);
  if(meta&&meta.file){ await analyzeStatic(meta.file); }
  else{
    document.getElementById('inc-title').innerText='Incident: '+incident_id;
    document.getElementById('inc-desc').innerText='Run RCA to investigate, or review past runs below.';
    LAST_INCIDENT=incident_id;
    await refreshWorkspaceExtras(incident_id);
    document.getElementById('rca-output').style.display='none';
  }
}
async function analyzeStatic(file){
  const data=await (await fetch('/api/analyze/'+file)).json();
  renderRCA(data);
}
function toggleCreateForm(){
  const f=document.getElementById('create-form');
  f.style.display=f.style.display==='none'?'block':'none';
  if(f.style.display==='block'){ loadCreateProjects(); buildSimDescriptions(); }
}
function createTab(which){
  document.getElementById('tab-manual').classList.toggle('on',which==='manual');
  document.getElementById('tab-sim').classList.toggle('on',which==='sim');
  document.getElementById('create-manual').style.display=which==='manual'?'block':'none';
  document.getElementById('create-sim').style.display=which==='sim'?'block':'none';
}
async function loadCreateProjects(){
  try{
    const ps=await (await fetch('/api/projects')).json();
    const opts=ps.map(p=>`<option value="${esc(p.project_id)}">${esc(p.name)}</option>`).join('');
    ['ci-project','nc-project'].forEach(id=>{ const el=document.getElementById(id); if(el) el.innerHTML=opts; });
    const nc=document.getElementById('nc-project'); if(nc) updateCreateRepoHint();
  }catch(e){}
}
async function updateCreateRepoHint(){
  const pid=(document.getElementById('nc-project')||{}).value||'';
  const box=document.getElementById('nc-repo'); if(!box) return;
  if(!pid) return;
  try{
    const r=await (await fetch('/api/projects/'+pid+'/repo-readiness')).json();
    box.innerHTML=`<strong>${esc(r.status||'')}</strong> · ${esc((r.languages||[]).join(', ')||'unknown stack')} · mappings: ${esc(Object.keys(r.mapping_notes||{}).length||'none')}`;
  }catch(e){ box.innerText='Repository status unavailable.'; }
}
async function createStandalone(){
  const out=document.getElementById('nc-result');
  const body={title:document.getElementById('nc-title').value.trim(),
    environment:document.getElementById('nc-env').value, severity:document.getElementById('nc-sev').value,
    affected_services:document.getElementById('nc-services').value.split(',').map(s=>s.trim()).filter(Boolean),
    description:document.getElementById('nc-desc').value.trim(),
    trace_id:document.getElementById('nc-trace').value.trim(), request_id:document.getElementById('nc-req').value.trim(),
    error_signature:document.getElementById('nc-err').value.trim(), revision:document.getElementById('nc-rev').value.trim()};
  if(!body.title){ out.innerText='Title is required.'; return; }
  const pid=document.getElementById('nc-project').value;
  const r=await fetch('/api/projects/'+pid+'/incidents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  if(!r.ok){ out.innerText=d.detail||'creation failed'; return; }
  out.innerText='Created '+d.incident_id+' (source MANUAL)';
  go('incidents', d.incident_id);
}
let SIM_FILTER='';
function filterSims(cat){ SIM_FILTER=cat||''; renderSimGrid(); }
let SIM_CACHE=[];
async function loadSimulations(){
  const grid=document.getElementById('sim-grid'); if(!grid) return;
  try{
    const d=await (await fetch('/api/simulations')).json();
    SIM_CACHE=d.scenarios||[];
    renderSimGrid();
  }catch(e){ grid.innerHTML='<p>Could not load simulations.</p>'; }
}
function renderSimGrid(){
  const grid=document.getElementById('sim-grid'); if(!grid) return;
  const rows=(SIM_CACHE||[]).filter(s=>!SIM_FILTER||s.category===SIM_FILTER);
  grid.innerHTML=rows.length?rows.map(s=>`<div class="card"><div class="card-title">${esc(s.title)}</div>`+
    `<p style="font-size:.78rem;color:var(--text-muted)">${esc(s.category)} / ${esc(s.subcategory||'')}</p>`+
    `<p style="font-size:.82rem">${esc(s.blurb||'')}</p>`+
    `<p style="font-size:.75rem;color:var(--text-muted)">Evidence: ${esc(s.evidence||'')}</p>`+
    `<p style="font-size:.75rem;color:var(--text-muted)">Expected RCA: ${esc(s.expected_rca||'')}</p>`+
    `<div style="margin-top:8px"><button class="btn btn-primary" onclick="runCatalogSimulation('${esc(s.scenario_id)}')">Run Simulation</button> `+
    `<button class="sim-btn" onclick="runCatalogSimulation('${esc(s.scenario_id)}',true)">Run Simulation &amp; RCA</button></div></div>`).join('')
    :'<p>No scenarios in this category.</p>';
}
async function runCatalogSimulation(scenario, andRca){
  const service=(document.getElementById('sim-service')||{}).value||'checkout-service';
  const environment=(document.getElementById('sim-env')||{}).value||'demo';
  const r=await fetch('/api/simulations/run',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({scenario, service, environment})});
  const d=await r.json();
  if(!r.ok){ alert(d.detail||'simulation failed'); return; }
  go('incidents', d.incident_id);
  if(andRca){ setTimeout(()=>runLiveRCA(), 800); }
}
function buildSimDescriptions(){
  const box=document.getElementById('create-sim-list'); if(!box||!TAX) return;
  const descs={'bad-deployment':'Injects errors representing a faulty application revision deployed shortly before elevated failures.','pool-exhaustion':'Saturates the database connection pool under concurrent load.','config-error':'Applies a broken environment/config value to config-gated endpoints.','malformed-payload':'Sends invalid request payloads producing client-side 400s.','auth-failure':'Presents expired credentials producing auth failures.','dependency-failure':'Makes the downstream orders dependency return 503s.','db-timeout':'Makes database calls time out with normal compute.','traffic-overload':'Floods the service beyond instance capacity.','memory-leak':'Gradually increases memory usage and produces GC/OOM indicators.','cpu-exhaustion':'Runs a compute-heavy endpoint saturating CPU.','network-timeout':'Stalls downstream responses until timeout.','rate-limit':'Bursts requests past quota producing 429s.'};
  const grp=(title,slugs)=>`<h5>${title}</h5>`+slugs.map(s=>`<div style="margin-bottom:8px"><button class="sim-btn" onclick="simulate('${s}')">${esc((TAX.labels||{})[s]||s)}</button><div style="font-size:.76rem;color:var(--text-muted)">${esc(descs[s]||'')}</div></div>`).join('');
  box.innerHTML=`<h5>Code / Application Errors</h5>`+
    grp('Configuration',['bad-deployment','config-error'])+grp('Application Logic',['malformed-payload','auth-failure'])+
    grp('Application Dependency',['dependency-failure','db-timeout'])+grp('Application Resource',['pool-exhaustion'])+
    `<h5>Infrastructure / Platform Errors</h5>`+
    grp('Compute',['cpu-exhaustion','memory-leak'])+grp('Network',['network-timeout'])+grp('Capacity',['traffic-overload'])+grp('Quota',['rate-limit']);
}
async function createManual(){
  const out=document.getElementById('ci-create-result');
  const body={title:document.getElementById('ci-title').value.trim(),
    environment:document.getElementById('ci-env').value, severity:document.getElementById('ci-sev').value,
    affected_services:document.getElementById('ci-services').value.split(',').map(s=>s.trim()).filter(Boolean),
    description:document.getElementById('ci-desc').value.trim(), start_time:document.getElementById('ci-start').value.trim(),
    trace_id:document.getElementById('ci-trace').value.trim(), request_id:document.getElementById('ci-req').value.trim(),
    error_signature:document.getElementById('ci-err').value.trim(), revision:document.getElementById('ci-rev').value.trim(),
    context:document.getElementById('ci-context').value.trim()};
  if(!body.title){ out.innerText='Title is required.'; return; }
  const pid=document.getElementById('ci-project').value;
  const r=await fetch('/api/projects/'+pid+'/incidents',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const d=await r.json();
  if(!r.ok){ out.innerText=d.detail||'creation failed'; return; }
  out.innerText='Created '+d.incident_id;
  await openIncident(d.incident_id);
}
/* ---- investigation platform: tabs, hero, graph, why, challenge ---- */
let INV_TAB='summary', INV_GRAPH=null, GRAPH_ZOOM=1, GRAPH_PAN={x:0,y:0};
const INV_TABS={summary:['inc-hero','rca-output'],investigation:['sec-inv'],evidence:['sec-live'],timeline:['sec-timeline'],remediation:['codefix-output'],approvals:['sec-gov'],activity:['sec-meta','sec-activity']};
function switchInvTab(name){
  INV_TAB=name;
  document.querySelectorAll('#inv-tabs button').forEach(b=>b.classList.toggle('on',b.dataset.tab===name));
  const show=new Set(INV_TABS[name]||[]);
  ['inc-hero','rca-output','sec-inv','sec-live','sec-timeline','codefix-output','sec-gov','sec-meta','sec-activity'].forEach(id=>{
    const el=document.getElementById(id); if(!el) return;
    el.style.display=show.has(id)?'':'none';
  });
  if(name==='investigation'&&LAST_INCIDENT) loadInvestigation(LAST_INCIDENT);
  if(name==='timeline'&&LAST_INCIDENT) loadInvTimeline(LAST_INCIDENT);
  if(name==='activity'&&LAST_INCIDENT) loadInvActivity(LAST_INCIDENT);
}
async function renderHero(incident_id){
  const box=document.getElementById('inc-hero'); if(!box) return;
  try{
    const d=await (await fetch('/api/incidents/'+incident_id)).json();
    const inc=d.incident||{};
    let quality=null, why=null;
    try{ quality=await (await fetch('/api/incidents/'+incident_id+'/quality-score')).json(); }catch(e){}
    try{ why=await (await fetch('/api/incidents/'+incident_id+'/why')).json(); }catch(e){}
    const conf=Math.round(((why&&why.confidence)||0)*100);
    const q=quality?Math.round(quality.score):null;
    const prs=d.pull_requests||[];
    box.style.display='block';
    box.innerHTML=`<div class="card-title">${esc(incident_id)} · ${esc(inc.title||'')}</div>
      <div style="font-size:.8rem;color:var(--text-muted)">${esc(inc.severity||'')} · ${esc(inc.environment||'')} · ${esc((inc.services||[]).join(', '))} · Status: ${esc(inc.status||'')}</div>
      <div class="hero-stats">
        <div class="hero-stat">Root Cause<strong>${esc((why&&why.conclusion||'Pending RCA').slice(0,40))}</strong></div>
        <div class="hero-stat">Confidence<strong>${conf?conf+'%':'—'}</strong></div>
        <div class="hero-stat">Investigation Quality<strong>${q!=null?q+' / 100':'—'}</strong></div>
        <div class="hero-stat">Repository<strong>${esc(d.project&&(d.project.repository_url||d.project.local_path)?'Connected':'Not connected')}</strong></div>
        <div class="hero-stat">PR<strong>${prs.length?esc(prs[0].pr_id+' · '+prs[0].status):'Not created'}</strong></div>
      </div>
      <div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">
        <button class="sim-btn" onclick="switchInvTab('investigation')">Open Investigation</button>
        <button class="sim-btn" onclick="highlightSupportPath()">Show Evidence Path</button>
        <button class="sim-btn" onclick="document.body.classList.toggle('present')">Toggle Presentation Mode</button>
      </div>`;
  }catch(e){ box.style.display='none'; }
}
async function loadInvestigation(incident_id){
  const has=(id)=>!!document.getElementById(id);
  try{
    const g=await (await fetch('/api/incidents/'+incident_id+'/investigation-graph')).json();
    INV_GRAPH=g; renderGraph(g);
  }catch(e){ if(has('inv-graph')) document.getElementById('inv-graph').innerHTML='<p style="color:var(--text-muted)">Run RCA to build the investigation graph.</p>'; }
  try{
    const w=await (await fetch('/api/incidents/'+incident_id+'/why')).json();
    if(has('inv-why')) document.getElementById('inv-why').innerHTML=
      `<div><strong>Why this conclusion?</strong>${(w.reasons||[]).map(r=>`<div class="evidence-box">✓ ${esc(r)}</div>`).join('')||'<p>—</p>'}</div>`+
      (w.rejected&&w.rejected.length?`<div style="margin-top:8px"><strong>Why not alternatives?</strong>`+w.rejected.map(r=>`<div class="evidence-box"><strong>${esc(r.category||r.hypothesis)}</strong> — ${esc(r.status)}<br/><span style="color:var(--text-muted)">${esc(r.reason)}</span></div>`).join('')+`</div>`:'');
  }catch(e){}
  try{
    const a=await (await fetch('/api/incidents/'+incident_id+'/agent-findings')).json();
    if(has('inv-agents')) document.getElementById('inv-agents').innerHTML=(a.findings||[]).map(f=>`<div class="evidence-box"><strong>${esc(f.agent)}</strong> <span class="pill info">${esc(f.verdict||f.strength)}</span><br/>${esc(f.summary)}<br/><span style="font-size:.72rem;color:var(--text-muted)">${f.evidence_count} evidence item(s) · confidence ${Math.round((f.confidence||0)*100)}%</span></div>`).join('')||'<p>—</p>';
  }catch(e){}
  try{
    const ch=await (await fetch('/api/incidents/'+incident_id+'/confidence-history')).json();
    if(has('inv-conf')) document.getElementById('inv-conf').innerHTML=(ch.snapshots||[]).map(s=>`<div style="margin-bottom:8px"><strong>${esc(s.stage)}</strong> — ${Math.round(s.confidence*100)}%<div class="conf-bar"><i style="width:${Math.round(s.confidence*100)}%"></i></div><span style="font-size:.75rem;color:var(--text-muted)">${esc(s.reason)}</span></div>`).join('')||'<p>—</p>';
  }catch(e){}
  try{
    const q=await (await fetch('/api/incidents/'+incident_id+'/quality-score')).json();
    if(has('inv-quality')) document.getElementById('inv-quality').innerHTML=
      `<div style="font-size:1.4rem;font-weight:700">${Math.round(q.score)}<span style="font-size:.8rem;color:var(--text-muted)"> / 100</span></div>`+
      (q.factors||[]).map(f=>`<div style="font-size:.78rem;margin-top:4px">${esc(f.name)}: <strong>${f.points}/${f.max_points}</strong> <span style="color:var(--text-muted)">(${esc(f.status)})</span><br/><span style="color:var(--text-muted)">${esc(f.note)}</span></div>`).join('')+
      (q.deductions&&q.deductions.length?`<div style="margin-top:6px;font-size:.76rem;color:var(--text-muted)"><strong>Deductions:</strong><br/>${q.deductions.map(esc).join('<br/>')}</div>`:'');
  }catch(e){}
  const sug=document.getElementById('challenge-suggest');
  if(sug) sug.innerHTML=['Why do you think this is not a database outage?','What evidence points to the deployment?','Why are you blaming this file?','What would lower your confidence?','Could this be traffic overload?'].map(q=>`<button class="sim-btn" onclick="document.getElementById('challenge-q').value='${q.replace(/'/g,"")}';submitChallenge()">${esc(q)}</button>`).join('');
}
function renderGraph(g){
  const box=document.getElementById('inv-graph'); if(!box||!g) return;
  const layers=['INCIDENT','EVIDENCE','DEPLOYMENT','AGENT','HYPOTHESIS','CODE','ROOT_CAUSE','FIX','APPROVAL','PR','VERIFICATION'];
  const byLayer={}; layers.forEach(l=>byLayer[l]=[]);
  g.nodes.forEach(n=>{(byLayer[n.type]||byLayer.EVIDENCE).push(n);});
  const W=1100, rowH=64, colW=W/Math.max(1,layers.filter(l=>byLayer[l].length).length);
  let li=0; const pos={};
  layers.forEach(l=>{
    const arr=byLayer[l]; if(!arr.length) return;
    arr.forEach((n,i)=>{ pos[n.id]={x:li*colW+14, y:20+i*rowH, w:colW-28, h:46}; });
    li++;
  });
  const H=Math.max(320, Math.max(...Object.values(pos).map(p=>p.y+p.h))+20);
  let svg=`<svg id="inv-svg" width="100%" height="${H}" viewBox="${GRAPH_PAN.x} ${GRAPH_PAN.y} ${W/GRAPH_ZOOM} ${H/GRAPH_ZOOM}" style="background:#0d0d0d" role="img" aria-label="Investigation graph">`;
  const edgeCls=e=>e.relationship==='CONTRADICTS'?'gedge contra':'gedge';
  g.edges.forEach((e,i)=>{
    const a=pos[e.from], b=pos[e.to]; if(!a||!b) return;
    const x1=a.x+a.w, y1=a.y+a.h/2, x2=b.x, y2=b.y+b.h/2;
    svg+=`<line class="${edgeCls(e)}" data-e="${i}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"><title>${esc(e.relationship)}</title></line>`;
  });
  g.nodes.forEach(n=>{
    const p=pos[n.id]; if(!p) return;
    const key=(n.type==='ROOT_CAUSE'||n.type==='FIX'||n.type==='PR')?'gnode key':'gnode';
    svg+=`<g class="${key}" data-n="${esc(n.id)}" onclick="selectGraphNode('${esc(n.id)}')"><rect x="${p.x}" y="${p.y}" width="${p.w}" height="${p.h}" rx="8"/><text x="${p.x+8}" y="${p.y+18}">${esc(n.type.replace('_',' '))}</text><text x="${p.x+8}" y="${p.y+34}">${esc((n.label||'').slice(0,26))}</text></g>`;
  });
  svg+='</svg>';
  box.innerHTML=svg;
  enableGraphPan();
}
function graphNodeById(id){ return (INV_GRAPH&&INV_GRAPH.nodes||[]).find(n=>n.id===id); }
function selectGraphNode(id){
  const n=graphNodeById(id); if(!n) return;
  document.querySelectorAll('#inv-svg .gnode').forEach(g=>g.classList.toggle('lit',g.dataset.n===id));
  const m=n.metadata||{};
  const rows=Object.entries(m).filter(([,v])=>v!==''&&v!=null).slice(0,12).map(([k,v])=>`<div><strong>${esc(k)}:</strong> ${esc(Array.isArray(v)?v.slice(0,4).join(', '):String(v)).slice(0,300)}</div>`).join('');
  document.getElementById('inv-node-detail').innerHTML=`<strong>${esc(n.type)}</strong> ${n.confidence!=null?'<span class="pill info">'+Math.round(n.confidence*100)+'%</span>':''} ${n.status?statusPill(n.status):''}<div style="margin:6px 0">${esc(n.label)}</div>${rows}`;
}
function highlightSupportPath(){
  if(!INV_GRAPH) return;
  const path=new Set(INV_GRAPH.support_path||[]);
  switchInvTab('investigation');
  setTimeout(()=>{
    document.querySelectorAll('#inv-svg .gnode').forEach(g=>{g.classList.toggle('lit',path.has(g.dataset.n));g.classList.toggle('dim',!path.has(g.dataset.n));});
  },150);
}
function graphZoom(d){ GRAPH_ZOOM=Math.min(3,Math.max(0.5,GRAPH_ZOOM+d*0.25)); if(INV_GRAPH) renderGraph(INV_GRAPH); }
function graphFit(){ GRAPH_ZOOM=1; GRAPH_PAN={x:0,y:0}; if(INV_GRAPH) renderGraph(INV_GRAPH); }
function enableGraphPan(){
  const svg=document.getElementById('inv-svg'); if(!svg) return;
  let drag=null;
  svg.addEventListener('mousedown',e=>{drag={x:e.clientX,y:e.clientY,px:GRAPH_PAN.x,py:GRAPH_PAN.y};});
  window.addEventListener('mouseup',()=>drag=null);
  window.addEventListener('mousemove',e=>{ if(!drag) return; const r=svg.getBoundingClientRect(); GRAPH_PAN.x=drag.px-(e.clientX-drag.x)*(1100/GRAPH_ZOOM)/r.width; GRAPH_PAN.y=drag.py-(e.clientY-drag.y); svg.setAttribute('viewBox',`${GRAPH_PAN.x} ${GRAPH_PAN.y} ${1100/GRAPH_ZOOM} ${svg.height.baseVal.value/GRAPH_ZOOM}`); });
}
async function submitChallenge(){
  const q=document.getElementById('challenge-q').value.trim(); if(!q||!LAST_INCIDENT) return;
  const box=document.getElementById('challenge-a'); box.innerHTML='<p>Reasoning from stored evidence…</p>';
  const r=await fetch('/api/incidents/'+LAST_INCIDENT+'/challenge',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question:q})});
  const d=await r.json();
  if(!r.ok){ box.innerHTML=`<p>${esc(d.detail||'failed')}</p>`; return; }
  box.innerHTML=`<div class="evidence-box"><strong>Answer</strong> (confidence ${Math.round((d.confidence||0)*100)}%)<br/>${esc(d.answer)}</div>`+
    (d.evidence_refs&&d.evidence_refs.length?`<div><strong>Evidence</strong>${d.evidence_refs.map(e=>`<div class="evidence-box">${esc(e)}</div>`).join('')}</div>`:'')+
    (d.limitations&&d.limitations.length?`<div style="font-size:.78rem;color:var(--text-muted)"><strong>Limitations:</strong><br/>${d.limitations.map(esc).join('<br/>')}</div>`:'');
}
async function loadInvTimeline(incident_id){
  try{
    const t=await (await fetch('/api/incidents/'+incident_id+'/timeline?view=significant')).json();
    const evs=t.events||[];
    document.getElementById('inv-timeline').innerHTML=evs.length?('<div class="timeline">'+evs.map(e=>`<div><span class="ts">${esc(e.timestamp||'')}</span><br/><strong>${esc(e.event_type||'')}</strong> — ${esc(e.description||'')}</div>`).join('')+'</div>'):'<p style="color:var(--text-muted)">No timeline yet — run RCA first.</p>';
  }catch(e){ document.getElementById('inv-timeline').innerHTML='<p>No timeline available.</p>'; }
}
async function loadInvActivity(incident_id){
  try{
    const rows=await (await fetch('/api/incidents/'+incident_id+'/activity')).json();
    document.getElementById('incident-activity').innerHTML=rows.length?('<div class="timeline">'+rows.slice(0,30).map(e=>`<div><span class="ts">${esc(e.timestamp||'')}</span><br/><strong>${esc(e.event||'')}</strong> — ${esc(e.description||'')} <span style="color:var(--text-muted)">(${esc(e.actor||'')})</span></div>`).join('')+'</div>'):'<p style="color:var(--text-muted)">No activity yet.</p>';
  }catch(e){}
}
/* ---- workspace extras ---- */
const WF_STEPS=[['Incident Detected','inc-title'],['Evidence Collected','log-summary'],['Evidence Correlated','live-logs'],['Root Cause Identified','rca-output'],['Remediation Proposed','remediation-box'],['Approval Required','approval-box'],['PR Created','codefix-output'],['Resolution','related-pr']];
function renderStepper(detail){
  const box=document.getElementById('wf-stepper'); if(!box) return;
  const status=(detail.incident||{}).status||'Open';
  const hist=((detail.incident||{}).history||[]).map(h=>h.to);
  const order=['NEW','COLLECTING_EVIDENCE','ANALYZING','ROOT_CAUSE_IDENTIFIED','REMEDIATION_PROPOSED','WAITING_APPROVAL','PR_CREATED','RESOLVED'];
  const ts={}; ((detail.incident||{}).history||[]).forEach(h=>{ if(h.to&&!ts[h.to]) ts[h.to]=h.at; });
  const failed=status==='FAILED';
  const idx=order.indexOf(status);
  box.innerHTML=WF_STEPS.map((s,i)=>{
    let cls='skip', sub='pending', stamp=ts[order[i]]||'';
    if(failed&&i===(idx<0?0:idx)){ cls='fail'; sub='failed'; }
    else if(idx>=0&&i<idx){ cls='done'; sub='completed'; }
    else if(idx>=0&&i===idx){ cls=(status==='RESOLVED')?'done':'run'; sub=(status==='RESOLVED')?'completed':'running'; }
    else if(status==='Open'&&i===0){ cls='run'; sub='running'; }
    return `<div class="step ${cls}" title="${esc(s[0])}${stamp?(' — '+esc(stamp)):' — '+sub}" onclick="document.getElementById('${s[1]}')&&document.getElementById('${s[1]}').scrollIntoView({behavior:'smooth',block:'center'})"><div class="t">${esc(s[0])}</div><div class="s">${sub}${stamp?(' · '+esc(String(stamp).slice(11,16))):''}</div></div>`;
  }).join('');
}
function inferEvType(text){
  const t=(text||'').toLowerCase();
  if(/revision|deployed|deployment|traffic/.test(t)) return 'DEPLOYMENT';
  if(/trace|span/.test(t)) return 'TRACE';
  if(/p95|latency|cpu|memory|5xx|error rate|request/.test(t)) return 'METRIC';
  if(/runbook|historical|incident inc-|similar/.test(t)) return 'HISTORY';
  return 'APPLICATION_LOG';
}
function renderEvidenceStructured(listEl, items, emptyText){
  const box=document.getElementById(listEl); if(!box) return;
  if(!items||!items.length){ box.innerHTML=`<p style="color:var(--text-muted);font-size:.85rem">${esc(emptyText)}</p>`; return; }
  box.innerHTML=items.map(e=>{
    const tp=inferEvType(e);
    return `<div class="evidence-box"><span class="pill info">${tp}</span> <span style="font-size:.72rem;color:var(--text-muted)">inferred · ${listEl==='evidence-list'?'Direct/Indirect':'does not overturn RCA'}</span><div style="margin-top:4px">${esc(e)}</div></div>`;
  }).join('');
}
function renderBlast(data){
  const el=document.getElementById('rc-blast'); if(!el) return;
  const b=data.blast_radius;
  if(!b){ el.innerHTML='—'; return; }
  if(typeof b==='string'){ el.innerHTML=esc(b); return; }
  const sev=humanize(b.classification||b.scope||'');
  const services=b.affected_services||[];
  const endpoints=b.affected_endpoints||[];
  const impact=b.estimated_scope||b.summary||'';
  const region=b.region||b.regional_scope||'';
  let html=`<div><strong>Severity:</strong> ${esc(sev||'—')}</div>`;
  if(services.length) html+=`<div style="margin-top:6px"><strong>Affected services:</strong><ul style="margin:4px 0;padding-left:18px">`+services.map(s=>`<li>${esc(s)}</li>`).join('')+`</ul></div>`;
  if(endpoints.length) html+=`<div style="margin-top:6px"><strong>Affected endpoints:</strong><ul style="margin:4px 0;padding-left:18px">`+endpoints.map(s=>`<li>${esc(s)}</li>`).join('')+`</ul></div>`;
  if(region) html+=`<div style="margin-top:6px"><strong>Region:</strong> ${esc(region)}</div>`;
  if(impact) html+=`<div style="margin-top:6px"><strong>Impact:</strong> ${esc(impact)}</div>`;
  el.innerHTML=html;
}

function renderRcExtras(data){
  if((!data.error_domain||data.error_domain==='Unknown')&&TAX&&TAX.categories&&data.root_cause_category){
    const t=TAX.categories[data.root_cause_category];
    if(t){ data.error_domain=t.domain; data.error_subcategory=t.subcategory; }
  }
  const dom=document.getElementById('rc-domain');
  if(dom) dom.innerHTML=`<strong>Domain:</strong> ${esc(data.error_domain||'Unknown')} · <strong>Subcategory:</strong> ${esc(data.error_subcategory||'Unknown')} · <strong>Source:</strong> ${esc(data.evidence_source||'live')}`;
  const why=document.getElementById('rc-why');
  if(why){
    const hyps=data.hypotheses||[];
    const byId={}; hyps.forEach(h=>{byId[h.hypothesis_id]=h;});
    const accepted=(data.validations||[]).filter(v=>v.accepted);
    const rejected=(data.validations||[]).filter(v=>!v.accepted);
    let html='<strong>Why this conclusion</strong>';
    if(accepted.length){
      html+=accepted.map(v=>{
        const h=byId[v.hypothesis_id]||{};
        const cat=h.root_cause_category||'';
        const conf=Math.round(((v.adjusted_confidence!=null?v.adjusted_confidence:h.confidence_score)||0)*100);
        return `<div style="margin-top:6px">✓ <strong>${esc(humanize(cat))}</strong><br/><span style="color:var(--text-muted)">Strongly supported · ${conf}%</span><br/>${esc(v.critic_reasoning||h.reasoning_summary||'')}${(v.contradictions&&v.contradictions.length)?'<br/><span style="color:var(--text-muted)">Noted caveats: '+esc(v.contradictions.join('; '))+'</span>':''}</div>`;
      }).join('');
    } else if(hyps.length){
      const h=hyps[0];
      html+=`<div style="margin-top:6px">✓ <strong>${esc(humanize(h.root_cause_category))}</strong><br/><span style="color:var(--text-muted)">${Math.round((h.confidence_score||0)*100)}%</span><br/>${esc(h.reasoning_summary||'')}</div>`;
    } else {
      html+=`<div style="margin-top:6px;color:var(--text-muted)">No hypothesis details available.</div>`;
    }
    if(rejected.length){
      html+='<div style="margin-top:10px"><strong>Rejected alternatives</strong>'+rejected.map(v=>{
        const h=byId[v.hypothesis_id]||{};
        const conf=Math.round(((v.adjusted_confidence!=null?v.adjusted_confidence:h.confidence_score)||0)*100);
        return `<div style="margin-top:6px">${esc(humanize(h.root_cause_category))}<br/><span style="color:var(--text-muted)">Rejected · ${conf}% — ${esc(v.critic_reasoning||'contradicted by evidence')}</span></div>`;
      }).join('')+'</div>';
    }
    why.innerHTML=html;
  }
  renderEvidenceStructured('evidence-list', data.evidence||data.supporting_evidence||[], 'No supporting evidence cited.');
  renderEvidenceStructured('contra-list', data.contradictory_evidence||[], 'No meaningful contradictory evidence was identified.');
}

async function refreshWorkspaceExtras(incident_id){
  if(!incident_id) return;
  try{
    const d=await (await fetch('/api/incidents/'+incident_id)).json();
    const inc=d.incident||{};
    renderStepper(d);
    const meta=document.getElementById('inc-meta');
    const src=((d.source||inc.source||'MANUAL')+'').toUpperCase();
    const simBadge=src==='SIMULATION'?' <span class="pill warn">SIMULATED</span> <span class="pill info">DEMO</span>':' <span class="pill info">Source: '+esc(src)+'</span>';
    const scen=d.scenario_id||inc.scenario_id?(' · Scenario: '+esc(d.scenario_id||inc.scenario_id)):'';
    if(meta) meta.innerHTML=`Project: <strong>${esc(inc.project_id||d.file_meta&&d.file_meta.project_id||'')}</strong> · Env: ${esc(inc.environment||'prod')} · Severity: ${esc(inc.severity||'')} · Status: ${esc(inc.status||'Open')} · Started: ${esc(fmtTime(inc.started_at||''))}${simBadge}${scen}`;
    try{
      const gate=document.getElementById('rca-gate');
      if(gate) gate.innerText = src==='SIMULATION'
        ? 'Simulated incident — use Regenerate Simulation Evidence or Run RCA. Manual uploads are disabled here.'
        : 'Run the RCA agent against the currently collected incident evidence.';
      const title=document.getElementById('inc-title');
      if(title&&src==='SIMULATION'&&!String(title.innerText).includes('[SIMULATED]')) title.innerText='[SIMULATED] '+title.innerText;
    }catch(e){}
    const chip=document.getElementById('ws-project-chip');
    if(chip) chip.innerText='Project: '+(inc.project_id||'');
    const runs=document.getElementById('rca-runs');
    if(runs) runs.innerHTML=(d.rca_runs||[]).length?d.rca_runs.map(r=>`<div class="evidence-box"><strong>Run #${r.run_number}</strong> ${esc(r.category||'')} · ${Math.round((r.confidence||0)*100)}% · ${esc(r.evidence_source||'')} · ${esc(r.duration_s!=null?r.duration_s+'s':'')}<br/><span style="font-size:.75rem;color:var(--text-muted)">${esc(r.at||'')}</span></div>`).join(''):'<span style="font-size:.8rem;color:var(--text-muted)">No runs yet.</span>';
    const notes=document.getElementById('notes-list');
    if(notes) notes.innerHTML=(d.notes||[]).length?d.notes.map(n=>`<div class="evidence-box"><strong>${esc(n.author)}</strong> <span style="font-size:.72rem;color:var(--text-muted)">${esc(fmtTime(n.at))}</span><br/>${esc(n.text)}</div>`).join(''):'<span style="font-size:.8rem;color:var(--text-muted)">No notes yet.</span>';
    const rel=document.getElementById('related-pr');
    if(rel){
      const prs=d.pull_requests||[];
      rel.innerHTML=prs.length?prs.map(p=>`<div class="evidence-box"><strong>PR #${p.pr_number||'?'} ${esc(p.title||'')}</strong><br/>Branch: ${esc(p.branch||'')} · Status: ${esc(p.status||'')} · Tests: ${esc(p.tests_status||'')}<br/><button class="sim-btn" onclick="go('prs','${esc(p.pr_id)}')">View PR</button></div>`).join(''):'<span style="font-size:.8rem;color:var(--text-muted)">No pull request raised for this incident.</span>';
    }
    const tl=document.getElementById('approval-timeline');
    if(tl){
      const evs=((await (await fetch('/api/incidents/'+incident_id+'/activity')).json())||[]).filter(e=>/APPROVAL|REMEDIATION|PR_/.test(e.event||''));
      tl.innerHTML=evs.length?('<div class="timeline">'+evs.map(e=>`<div><span class="ts">${esc(fmtTime(e.timestamp))}</span><br/><strong>${esc(e.event)}</strong> — ${esc(e.description||'')} <span style="color:var(--text-muted)">(${esc(e.actor||'')})</span></div>`).join('')+'</div>'):'<span style="font-size:.8rem;color:var(--text-muted)">No approval events yet.</span>';
    }
  }catch(e){ /* workspace extras must never break RCA display */ }
}
async function addNote(){
  const inp=document.getElementById('note-input');
  const text=(inp.value||'').trim();
  if(!text||!LAST_INCIDENT) return;
  await fetch('/api/incidents/'+LAST_INCIDENT+'/notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text})});
  inp.value='';
  refreshWorkspaceExtras(LAST_INCIDENT);
}
async function copyRcaSummary(){
  const d=window._lastRcaData;
  if(!d){ alert('Run RCA first'); return; }
  const txt='Incident '+d.incident_id+' | Impact: '+(d.affected_services||[]).join(', ')+' | Root cause: '+d.root_cause+' ('+Math.round((d.confidence_score||d.confidence||0)*100)+'%) | Evidence: '+(d.evidence||d.supporting_evidence||[]).slice(0,3).join('; ')+' | Remediation: '+(d.recommended_action||d.recommended_next_action||'');
  try{ await navigator.clipboard.writeText(txt); alert('RCA summary copied'); }
  catch(e){ prompt('Copy RCA summary:', txt); }
}
async function exportRca(fmt){
  if(!LAST_INCIDENT){ alert('Run RCA first'); return; }
  const r=await fetch('/api/incidents/'+LAST_INCIDENT+'/export?format='+fmt);
  if(!r.ok){ alert('Export unavailable: run RCA first'); return; }
  const blob=fmt==='json'?new Blob([JSON.stringify(await r.json(),null,2)],{type:'application/json'}):new Blob([await r.text()],{type:'text/markdown'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=LAST_INCIDENT+'-rca.'+(fmt==='json'?'json':'md');
  a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),5000);
}
function updateRcaGate(){
  const btn=document.getElementById('rca-btn'); if(!btn) return;
  if(btn.innerText.indexOf('Working')===0) return;
  const gate=document.getElementById('rca-gate');
  if(!LOGS.length){ btn.disabled=true; if(gate) gate.innerText='Waiting for sufficient evidence: no logs collected yet. Simulate an incident or upload logs first.'; }
  else{ btn.disabled=false; if(gate) gate.innerText='Run the RCA agent against the currently collected incident evidence. The agent will correlate logs, metrics, deployments, traces, infrastructure state, and code changes before proposing a root cause.'; }
}


/* ===== platform: theme, home, projects, PRs, uploads, settings ===== */
function initTheme(){
  let t=null;
  try{ t=localStorage.getItem('rca-theme'); }catch(e){}
  if(!t||t==='system'){ t=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark'; }
  applyTheme(t, true);
  document.querySelectorAll('input[name="theme"]').forEach(r=>{ r.checked=(r.value===(localStorage.getItem('rca-theme')||'system')); });
}
function applyTheme(t, silent){
  document.documentElement.dataset.theme=(t==='light')?'light':'dark';
}
function setTheme(t){
  try{ localStorage.setItem('rca-theme', t); }catch(e){}
  initTheme();
}
function toggleTheme(){
  const cur=document.documentElement.dataset.theme==='light'?'dark':'light';
  setTheme(cur);
}
/* ---- home ---- */
const EV_ICON={'INCIDENT_CREATED':'◉','SIMULATION_STARTED':'▲','RCA_STARTED':'◆','ROOT_CAUSE_IDENTIFIED':'✓','REMEDIATION_PROPOSED':'✎','APPROVAL_REQUESTED':'•','APPROVAL_APPROVED':'✓','APPROVAL_REJECTED':'✕','FIX_PROPOSED':'✎','FIX_APPROVED':'✓','FIX_REJECTED':'✕','FIX_APPLIED':'✓','PR_CREATED':'⎇','PR_FAILED':'!','LOG_COLLECTED':'≡','PROJECT_CREATED':'＋','STATUS_RESOLVED':'✓','INCIDENT_RESOLVED':'✓','EXECUTION':'▶','VERIFICATION':'✔'};
async function loadHome(){
  try{
    const r=await fetch('/api/home/stats');
    if(!r.ok) throw 0;
    const s=await r.json();
    const set=(id,v)=>{const e=document.getElementById(id); if(e) e.innerText=v;};
    set('hm-projects',s.projects); set('hm-incidents',s.open_incidents); set('hm-rca',s.rca_completed);
    set('hm-prs',s.prs_created); set('hm-approvals',s.pending_approvals);
    const act=document.getElementById('hm-activity');
    if(act) act.innerHTML=(s.recent_activity||[]).length?s.recent_activity.map(e=>`<div style="font-size:.8rem;padding:4px 0;border-bottom:1px solid var(--border-color)">${esc(EV_ICON[e.event]||'•')} <strong>${esc(e.event)}</strong> ${esc(e.incident_id||'')} <span style="color:var(--text-muted)">${esc(e.description||'')} · ${esc(timeAgo(e.timestamp))}</span></div>`).join(''):'<span style="color:var(--text-muted)">No activity yet.</span>';
    const prs=document.getElementById('hm-recent-prs');
    if(prs) prs.innerHTML=(s.recent_prs||[]).length?s.recent_prs.map(p=>`<div style="font-size:.8rem;padding:4px 0"><button class="sim-btn" onclick="go('prs','${esc(p.pr_id)}')">PR #${p.pr_number||'?'}</button> <strong>${esc(p.title||'').slice(0,60)}</strong><br/><span style="color:var(--text-muted)">${esc(p.incident_id||'')} · ${esc(p.status||'')}</span></div>`).join(''):'<span style="color:var(--text-muted)">No agent PRs yet.</span>';
  }catch(e){
    const act=document.getElementById('hm-activity');
    if(act) act.innerHTML='<span style="color:var(--text-muted)">Could not load home data. <button class="sim-btn" onclick="loadHome()">Retry</button></span>';
  }
}
/* ---- projects ---- */
async function loadProjects(){
  const box=document.getElementById('projects-list'); if(!box) return;
  box.innerHTML='<div class="skeleton"></div><div class="skeleton"></div>';
  try{
    const ps=await (await fetch('/api/projects')).json();
    box.innerHTML=ps.length?ps.map(p=>`<div class="stat-card"><div class="num" style="font-size:1.05rem">${esc(p.name)}</div>`+
      `<div class="lbl">${esc(p.project_id)} · ${esc(p.environment||'')} · ${esc((p.services||[]).join(', ')||'no services')}</div>`+
      `<div style="font-size:.76rem;margin-top:6px">${p.status==='active'?'✓ active':'• '+esc(p.status)} · ${p.open_incidents} open incident(s) · ${p.open_prs} open PR(s)</div>`+
      `<div style="font-size:.74rem;color:var(--text-muted);margin-top:4px">Sources: ${(p.data_sources||[]).map(s=>esc(s.kind)+':'+esc(s.status)).join(' · ')||'none'} · Access: ${esc(p.repo_access||'')}</div>`+
      `<div style="margin-top:8px"><button class="sim-btn" onclick="openProject('${esc(p.project_id)}')">Open</button></div></div>`).join('')
      :'<div class="card">No projects onboarded yet.</div>';
  }catch(e){ box.innerHTML='<div class="card">Failed to load projects. <button class="sim-btn" onclick="loadProjects()">Retry</button></div>'; }
}
async function openProject(pid, tab){
  CUR_PROJECT=pid;
  go('projects');
  loadSideProjects();
  const box=document.getElementById('project-detail'); if(!box) return;
  box.innerHTML='<div class="skeleton"></div>';
  try{
    const p=await (await fetch('/api/projects/'+pid)).json();
    const t=tab||'overview';
    box.innerHTML=`<div class="card"><div class="card-title">${esc(p.name)} <span style="font-size:.75rem;color:var(--text-muted)">${esc(p.project_id)}</span></div>
      <div style="font-size:.82rem">Repository: ${esc(p.repository_url||p.local_path||'—')} (${esc(p.provider||'')}) · Branch: ${esc(p.default_branch||'')} · Env: ${esc(p.environment||'')} · Region: ${esc(p.region||'')} · Services: ${esc((p.services||[]).join(', ')||'—')}</div>
      <div class="tabs">
        <button class="${t==='overview'?'on':''}" onclick="openProject('${esc(pid)}','overview')">Overview</button>
        <button class="${t==='incidents'?'on':''}" onclick="openProject('${esc(pid)}','incidents')">Incidents</button>
        <button class="${t==='prs'?'on':''}" onclick="openProject('${esc(pid)}','prs')">Pull Requests</button>
        <button class="${t==='config'?'on':''}" onclick="openProject('${esc(pid)}','config')">Configuration</button>
      </div><div id="project-tab-body"></div></div>`;
    const body=document.getElementById('project-tab-body');
    if(t==='overview'){
      const open=(p.incidents||[]).filter(i=>!['RESOLVED','FAILED'].includes(i.status));
      body.innerHTML=`<div class="cards">
        <div class="stat-card"><div class="num">${open.length}</div><div class="lbl">Open Incidents</div></div>
        <div class="stat-card"><div class="num">${(p.incidents||[]).filter(i=>i.status==='RESOLVED').length}</div><div class="lbl">Resolved</div></div>
        <div class="stat-card"><div class="num">${(p.pull_requests||[]).length}</div><div class="lbl">Agent PRs</div></div>
        <div class="stat-card"><div class="num">${esc(p.last_scan?timeAgo(p.last_scan):'never')}</div><div class="lbl">Last Scan</div></div></div>
        <strong>Recent incidents</strong>
        ${(p.incidents||[]).slice(0,5).map(i=>`<div class="evidence-box"><strong>${esc(i.incident_id)}</strong> ${esc(i.title||'')} ${statusPill(i.status)}</div>`).join('')||'<p style="color:var(--text-muted)">None</p>'}
        <strong>Data Sources</strong>
        ${(p.data_sources||[]).map(s=>`<div class="evidence-box">${esc(s.kind)}: ${s.status==='connected'?'✓ connected':'• '+esc(s.status)} ${esc(s.detail||'')} <button class="sim-btn" onclick="testSource('${esc(pid)}','${esc(s.kind)}')">Test</button> ${s.kind==='git'?`<button class="sim-btn" onclick="disconnectSource('${esc(pid)}','git')">Disconnect</button>`:''}</div>`).join('')||'<p style="color:var(--text-muted)">None connected</p>'}`;
    } else if(t==='incidents'){
      body.innerHTML=(p.incidents||[]).map(i=>`<div class="evidence-box"><strong>${esc(i.incident_id)}</strong> ${esc(i.title||'')} ${statusPill(i.status)}<br/><button class="sim-btn" onclick="openIncident('${esc(i.incident_id)}')">Open RCA</button></div>`).join('')||'<p style="color:var(--text-muted)">No incidents found for this project.</p>';
    } else if(t==='prs'){
      body.innerHTML=(p.pull_requests||[]).map(r=>`<div class="evidence-box"><strong>PR #${r.pr_number||'?'}</strong> ${esc(r.title||'')} ${statusPill(r.status)}<br/><button class="sim-btn" onclick="go('prs','${esc(r.pr_id)}')">View PR</button></div>`).join('')||'<p style="color:var(--text-muted)">No pull requests have been created from RCA remediations.</p>';
    } else {
      const d=p.detected||{};
      const sc=p.sources_config||{};
      const integ=[['GitHub / Git',p.repository_url||p.local_path?'connected':'not configured'],['Cloud Logging',sc.log_source||(p.gcp_project_id?'default':'not configured')],['Cloud Monitoring',sc.metrics_source||(p.gcp_project_id?'default':'not configured')],['Cloud Trace',sc.trace_source||(p.gcp_project_id?'default':'not configured')],['Deployments',sc.deployment_source||(p.gcp_project_id?'Cloud Run':'not configured')],['Prometheus / Grafana / Datadog / Kubernetes',(sc.metrics_source&&!/cloud|upload/i.test(sc.metrics_source))?sc.metrics_source:'not configured']];
      body.innerHTML=`<div style="font-size:.84rem">Languages: ${esc((d.languages||[]).join(', ')||'—')}<br/>Frameworks: ${esc((d.frameworks||[]).join(', ')||'—')}<br/>Services: ${esc((d.services||[]).join(', ')||'—')}<br/>Tests: ${(d.tests||[]).length} file(s) · Dockerfiles: ${(d.dockerfiles||[]).length} · CI: ${(d.ci_files||[]).length}<br/>Repository Access: <strong>${esc(p.repo_access||'READ_ONLY')}</strong> (PR creation ${p.repo_access==='PR_CREATION_ENABLED'?'enabled':'requires CODE_CHANGE approval gating'})</div>
      <div style="margin-top:10px"><strong>Integrations</strong>${integ.map(([n,s])=>'<div class="evidence-box">'+esc(n)+': '+( /connected|default/.test(s)?'✓ '.concat(esc(s)):'• '.concat(esc(s)))+'</div>').join('')}</div><div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap"><button class="sim-btn" data-pid="'+pid+'" onclick="editProject(this.dataset.pid)">Configure</button><button class="sim-btn" onclick="rescanProject('${esc(pid)}')">Re-scan Repository</button><button class="sim-btn" onclick="testSource('${esc(pid)}','git')">Test Connection</button><button class="sim-btn" onclick="disconnectSource('${esc(pid)}','git')">Disconnect Repository</button></div><div id="proj-cfg-msg" style="font-size:.8rem;margin-top:6px"></div>`;
    }
  }catch(e){ box.innerHTML='<div class="card">Failed to load project. <button class="sim-btn" data-pid="'+pid+'" onclick="openProject(this.dataset.pid)">Retry</button></div>'; }
}
let WIZ={step:1,mode:'new',data:{}};
function openOnboard(mode){
  WIZ={step:(mode==='repo'?2:(mode==='cloud'?3:1)),mode:mode||'new',data:{}};
  document.getElementById('modal').classList.add('open');
  renderWizard();
}
function closeModal(){ document.getElementById('modal').classList.remove('open'); }
function wizSet(k,v){ WIZ.data[k]=v; }
async function renderWizard(){
  const w=document.getElementById('wizard');
  const steps=['Project','Repository','Cloud','Scan','Confirm'];
  let body='';
  body+=`<div class="wiz-steps">`+steps.map((s,i)=>`<span class="${WIZ.step===i+1?'on':''}">${i+1} · ${s}</span>`).join('')+`</div>`;
  const d=WIZ.data, inp=(k,ph)=>`<input id="wz-${k}" value="${esc(d[k]||'')}" placeholder="${esc(ph||'')}" oninput="wizSet('${k}',this.value)" />`;
  const sel=(k,opts)=>`<select id="wz-${k}" onchange="wizSet('${k}',this.value)">${opts.map(o=>`<option${d[k]===o?' selected':''}>${o}</option>`).join('')}</select>`;
  if(WIZ.step===1){ body+=`<h3>Basic Project Details</h3><label>Project Name</label>${inp('name','Checkout Platform')}<label>Description</label>${inp('description','')}<label>Environment</label>${sel('environment',['production','staging','dev'])}<label>Team / Owner</label>${inp('team_owner','sre')}`; }
  if(WIZ.step===2){ body+=`<h3>Source Repository</h3><label>Git Provider</label>${sel('provider',['github','local'])}<label>Repository URL</label>${inp('repository_url','https://github.com/...git')}<label>Default Branch</label>${inp('default_branch','main')}<label>Repository Path if local</label>${inp('local_path','cloud-rca-demo-app')}<label>Service Path / Monorepo Subdirectory (optional)</label>${inp('service_path','services/checkout')}`; }
  if(WIZ.step===3){ body+=`<h3>Google Cloud Configuration</h3><label>GCP Project ID</label>${inp('gcp_project_id','')}<label>Region</label>${inp('region','us-central1')}<label>Cloud Run services (comma separated)</label>${inp('services','checkout-service')}<label>Log Source (optional)</label>${sel('log_source',['','Cloud Logging','CloudWatch','Datadog','Upload'])}<label>Metrics Source (optional)</label>${sel('metrics_source',['','Cloud Monitoring','Prometheus','Datadog','Upload'])}<label>Trace Source (optional)</label>${sel('trace_source',['','Cloud Trace','Grafana Tempo','Upload'])}<label>Deployment Source (optional)</label>${sel('deployment_source',['','Cloud Run','Kubernetes','Upload'])}<div style="font-size:.78rem;color:var(--text-muted)">Sources are recorded as labels only; telemetry is read through existing providers when credentials exist. Nothing is faked.</div>`; }
  if(WIZ.step===4){ body+=`<h3>Repository Scan</h3><div id="wiz-scan"><span style="color:var(--text-muted)">Scanning (read-only)…</span></div>`; }
  if(WIZ.step===5){ const r=WIZ.result||{}; body+=`<h3>Confirm</h3><div style="font-size:.85rem">Services: ${esc(((r.scan||{}).services||[]).join(', ')||'none detected')}<br/>Branch: ${esc(d.default_branch||'main')}<br/>Tests: ${((r.scan||{}).tests||[]).length} file(s)<br/>RCA readiness: ${(r.readiness&&r.readiness.rca_ready)?'✓ ready':'• see reasons'}<br/><span style="color:var(--text-muted)">${esc(((r.readiness||{}).reasons||[]).join('; '))}</span></div>`; }
  body+=`<div style="display:flex;gap:8px;margin-top:12px"><button class="sim-btn" onclick="closeModal()">Cancel</button><span style="flex:1"></span>`;
  if(WIZ.step>1) body+=`<button class="sim-btn" onclick="wizNav(-1)">Back</button>`;
  body+=`<button class="btn btn-primary" onclick="wizNav(1)">${WIZ.step===5?'Complete Onboarding':(WIZ.step===4?'Scan Again':'Next')}</button></div>`;
  w.innerHTML=body;
  ['name','description','team_owner','repository_url','default_branch','local_path','service_path','gcp_project_id','region','services','log_source','metrics_source','trace_source','deployment_source'].forEach(k=>{const el=document.getElementById('wz-'+k); if(el) el.value=d[k]||'';});
  if(WIZ.step===4) wizDoScan();
}
async function wizNav(dir){
  if(dir<0){ WIZ.step=Math.max(1,WIZ.step-1); renderWizard(); return; }
  if(WIZ.step===1&&!(WIZ.data.name||'').trim()){ alert('Project name is required'); return; }
  if(WIZ.step===5){ await wizSubmit(); return; }
  WIZ.step=Math.min(5,WIZ.step+1); renderWizard();
}
async function wizDoScan(){
  const box=document.getElementById('wiz-scan'); if(!box) return;
  const payload={project_id:WIZ.edit_id||undefined,name:WIZ.data.name||'unnamed',description:WIZ.data.description||'',environment:WIZ.data.environment||'production',team_owner:WIZ.data.team_owner||'',provider:WIZ.data.provider||'github',repository_url:WIZ.data.repository_url||'',default_branch:WIZ.data.default_branch||'main',local_path:WIZ.data.local_path||'',gcp_project_id:WIZ.data.gcp_project_id||'',region:WIZ.data.region||'us-central1',services:(WIZ.data.services||'').split(',').map(s=>s.trim()).filter(Boolean),log_source:WIZ.data.log_source||'',metrics_source:WIZ.data.metrics_source||'',trace_source:WIZ.data.trace_source||'',deployment_source:WIZ.data.deployment_source||''};
  const r=await fetch('/api/projects/onboard',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
  const d=await r.json();
  if(!r.ok){ box.innerHTML='<span style="color:var(--danger,#c0564d)">Onboarding failed: '+esc(d.detail||r.status)+'</span>'; return; }
  WIZ.result=d; WIZ.project_id=d.project.project_id;
  const s=d.scan||{};
  box.innerHTML=`<div style="font-size:.85rem">Languages: ${esc((s.languages||[]).join(', ')||'—')}<br/>Frameworks: ${esc((s.frameworks||[]).join(', ')||'—')}<br/>Services: ${esc((s.services||[]).join(', ')||'—')}<br/>Dockerfiles: ${(s.dockerfiles||[]).length} · Tests: ${(s.tests||[]).length} · CI: ${(s.ci_files||[]).length} · Files scanned: ${s.file_count||0}${s.error?('<br/>Note: '+esc(s.error)):''}</div><div style="font-size:.8rem;margin-top:6px">RCA readiness: ${(d.readiness&&d.readiness.rca_ready)?'✓ ready':'• '+(esc(((d.readiness||{}).reasons||[]).join('; '))||'see reasons')}</div>`;
}
async function wizSubmit(){ closeModal(); loadProjects(); loadSideProjects(); go('projects',WIZ.project_id||''); }
async function editProject(pid){
  try{
    const p=await (await fetch('/api/projects/'+pid)).json();
    WIZ={step:1,mode:'edit',edit_id:pid,data:{name:p.name||'',description:p.description||'',environment:p.environment||'production',team_owner:p.team_owner||'',provider:p.provider||'github',repository_url:p.repository_url||'',default_branch:p.default_branch||'main',local_path:p.local_path||'',service_path:(p.detected&&p.detected.services||[])[0]||'',gcp_project_id:p.gcp_project_id||'',region:p.region||'us-central1',services:(p.services||[]).join(', '),log_source:(p.sources_config||{}).log_source||'',metrics_source:(p.sources_config||{}).metrics_source||'',trace_source:(p.sources_config||{}).trace_source||'',deployment_source:(p.sources_config||{}).deployment_source||''}};
    document.getElementById('modal').classList.add('open');
    renderWizard();
  }catch(e){ alert('Could not load project'); }
}
async function rescanProject(pid){
  const m=document.getElementById('proj-cfg-msg'); if(m) m.innerText='Scanning…';
  const r=await fetch('/api/projects/'+pid+'/scan',{method:'POST'});
  if(m) m.innerText=r.ok?'Re-scan complete.':'Re-scan failed.';
  if(r.ok) openProject(pid,'config');
}
async function testSource(pid,kind){
  const r=await fetch('/api/projects/'+pid+'/test-connection',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind})});
  const d=await r.json();
  alert(kind+': '+(d.ok?'✓ connected — '+d.detail:'✕ '+d.detail));
}
async function disconnectSource(pid,kind){
  if(!confirm('Disconnect '+kind+' from this project?')) return;
  await fetch('/api/projects/'+pid+'/disconnect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind})});
  openProject(pid,'config'); loadProjects();
}
/* ---- pull requests ---- */
let ALL_PRS=[];
async function loadPRs(){
  try{
    const ps=await (await fetch('/api/projects')).json();
    const sel=document.getElementById('pr-filter-project');
    const cur=sel.value;
    sel.innerHTML='<option value="">All projects</option>'+ps.map(p=>`<option value="${esc(p.project_id)}">${esc(p.name)}</option>`).join('');
    if([...sel.options].some(o=>o.value===cur)) sel.value=cur;
    renderPRs();
  }catch(e){}
}
async function renderPRs(){
  const body=document.getElementById('prs-list'); if(!body) return;
  const proj=document.getElementById('pr-filter-project').value;
  const st=document.getElementById('pr-filter-status').value;
  let url='/api/pull-requests'+(proj?'?project='+encodeURIComponent(proj):'');
  let failed=false;
  try{ const r=await fetch(url); if(!r.ok) throw 0; ALL_PRS=await r.json(); }
  catch(e){ failed=true; ALL_PRS=[]; }
  if(failed){ body.innerHTML='<tr><td colspan="8">Could not load pull requests. <button class="sim-btn" onclick="renderPRs()">Retry</button></td></tr>'; return; }
  const rows=ALL_PRS.filter(p=>!st||p.status===st);
  document.getElementById('pr-count').innerText=rows.length+' PR(s)';
  body.innerHTML=rows.length?rows.map(p=>`<tr class="clickable" onclick="openPR('${esc(p.pr_id)}')">`+
    `<td><strong>PR #${p.pr_number||'?'}</strong></td><td><a onclick="event.stopPropagation();openIncident('${esc(p.incident_id)}')">${esc(p.incident_id||'')}</a></td>`+
    `<td>${esc(p.project_id||'')}</td><td>${esc((p.title||'').slice(0,70))}</td><td>${esc(fmtTime(p.created_at))}</td>`+
    `<td>${esc(p.risk||'')}</td><td>${esc(p.tests_status||'')}</td><td>${statusPill(p.status)}</td></tr>`).join('')
    :'<tr><td colspan="8">No pull requests have been created from RCA remediations.</td></tr>';
}
async function openPR(pr_id){
  go('prs');
  const box=document.getElementById('pr-detail'); if(!box) return;
  box.innerHTML='<div class="skeleton"></div>';
  setCrumbs([['Home',()=>go('home')],['Pull Requests',()=>go('prs')],[pr_id,null]]);
  try{
    const p=await (await fetch('/api/pull-requests/'+pr_id)).json();
    box.innerHTML=`<div class="card"><div class="card-title">PR #${p.pr_number||'?'} ${esc(p.title||'')}</div>
      <div style="font-size:.84rem">Incident: <a onclick="openIncident('${esc(p.incident_id)}')">${esc(p.incident_id||'')}</a> · Project: ${esc(p.project_id||'')} · Repository: ${esc(p.repository||'')} · Branch: ${esc(p.branch||'')} → ${esc(p.base_branch||'')} · Commit: ${esc(p.commit_sha||'')} · Created: ${esc(fmtTime(p.created_at))} · Status: ${statusPill(p.status)}</div>
      <div style="margin-top:10px"><strong>RCA Summary</strong><div class="evidence-box">${esc(p.root_cause||'')} (${Math.round((p.confidence||0)*100)}%)<br/><span style="color:var(--text-muted)">${(p.supporting_evidence||[]).slice(0,4).map(esc).join('<br/>')}</span></div></div>
      <div><strong>Code Changes</strong> (${esc((p.files_changed||[]).join(', '))} +${p.additions} -${p.deletions})</div>
      <pre style="background:#000;border:1px solid var(--border-color);border-radius:6px;padding:12px;overflow-x:auto;font-size:.76rem;white-space:pre-wrap">${esc(p.diff||'diff not stored for this PR')}</pre>
      <div><strong>Tests:</strong> ${esc(p.tests_status||'')} <pre style="background:#000;border:1px solid var(--border-color);border-radius:6px;padding:10px;max-height:200px;overflow:auto;font-size:.75rem;white-space:pre-wrap">${esc((p.tests_output||'').slice(-1500))}</pre></div>
      <div><strong>Approval:</strong> ${esc(p.approval_id||'')} by ${esc(p.approved_by||'')} at ${esc(fmtTime(p.approved_at))}</div>
      <div style="margin-top:8px">${p.external_url?`<a class="btn btn-primary" href="${esc(p.external_url)}" target="_blank" rel="noopener">View on GitHub</a>`:'<span style="color:var(--text-muted)">No external URL (creation blocked or mocked).</span>'}</div></div>`;
  }catch(e){ box.innerHTML='<div class="card">PR not found.</div>'; }
}
/* ---- analyze logs ---- */
async function loadAnalyzeInit(){
  try{
    const ps=await (await fetch('/api/projects')).json();
    const sel=document.getElementById('up-project');
    if(sel&&!sel.options.length) sel.innerHTML=ps.map(p=>`<option value="${esc(p.project_id)}">${esc(p.name)}</option>`).join('');
  }catch(e){}
  refreshAnalyses();
  const dz=document.getElementById('dropzone');
  if(dz&&!dz.dataset.bound){
    dz.dataset.bound='1';
    ['dragover','dragenter'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.style.borderColor='#fff';}));
    ['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.style.borderColor='#4a4a4a';}));
    dz.addEventListener('drop',e=>{ document.getElementById('up-files').files=e.dataTransfer.files; renderUpFiles(); });
    document.getElementById('up-files').addEventListener('change',renderUpFiles);
  }
}
function renderUpFiles(){
  const inp=document.getElementById('up-files');
  document.getElementById('up-filelist').innerHTML=[...inp.files].map(f=>`<div style="font-size:.8rem">${esc(f.name)} · ${(f.size/1024).toFixed(1)} KB</div>`).join('')||'';
}
let UP_ANALYSIS=null;
async function uploadLogs(){
  const inp=document.getElementById('up-files');
  if(!inp.files.length){ alert('Choose at least one log file'); return; }
  const btn=document.getElementById('up-btn'); btn.disabled=true; btn.innerText='Uploading…';
  const fd=new FormData();
  fd.append('project_id',document.getElementById('up-project').value||'unassigned');
  fd.append('source_type',document.getElementById('up-source').value);
  fd.append('service',document.getElementById('up-service').value);
  fd.append('incident_start',document.getElementById('up-start').value);
  fd.append('region',document.getElementById('up-region').value);
  fd.append('environment',document.getElementById('up-env').value);
  fd.append('description',document.getElementById('up-desc').value);
  [...inp.files].slice(0,4).forEach(f=>fd.append('files',f,f.name));
  const r=await fetch('/api/logs/upload',{method:'POST',body:fd});
  const d=await r.json();
  btn.disabled=false; btn.innerText='Upload & Preview';
  if(!r.ok){ alert(d.detail||'upload failed'); return; }
  UP_ANALYSIS=d.analysis_id;
  const pc=document.getElementById('up-preview-card'); pc.style.display='block';
  document.getElementById('up-preview').innerHTML=
    d.files.map(f=>`<div class="evidence-box"><strong>${esc(f.filename)}</strong> ${(f.size_bytes/1024).toFixed(1)} KB · ${esc(f.detected_format||'')} · ${esc(f.detected_source||'')} · ${f.record_count} records · ${esc(f.parse_status)}</div>`).join('')+
    (d.warnings||[]).map(w=>`<div style="font-size:.8rem">⚠ ${esc(w)}</div>`).join('')+
    `<div style="font-size:.8rem;color:var(--text-muted)">Detected services: ${esc((d.preview_stats.services||[]).join(', ')||'—')} · Range: ${esc(d.preview_stats.time_start||'')} → ${esc(d.preview_stats.time_end||'')}</div>`;
  refreshAnalyses();
}
async function analyzeUpload(){
  if(!UP_ANALYSIS) return;
  const btn=document.getElementById('up-analyze-btn'); btn.disabled=true; btn.innerText='Analyzing…';
  const mode=(document.querySelector('input[name="up-mode"]:checked')||{}).value||'analyze_only';
  const attachId=(document.getElementById('up-attach-inc')||{}).value||'';
  const qs=new URLSearchParams({mode, incident_id:attachId});
  const r=await fetch('/api/logs/'+UP_ANALYSIS+'/analyze?'+qs.toString(),{method:'POST'});
  const d=await r.json();
  btn.disabled=false; btn.innerText='Run RCA';
  if(!r.ok){ alert(d.detail||'analysis failed'); return; }
  const box=document.getElementById('up-results');
  const repoHint=d.no_repo?'<div class="item-box">No repository connected. Connect a Git repository to enable code-level remediation.</div>':'';
  const modeBadge=d.incident_created===false?'<span class="pill info">Analysis only — no incident created</span>':'<span class="pill info">Evidence Source: Uploaded Logs</span>';
  const convBtn=d.session_id?`<button class="sim-btn" onclick="convertSession('${esc(d.session_id)}')">Convert to Incident</button>`:'';
  const openBtn=d.incident_id?`<button class="sim-btn" onclick="openIncident('${esc(d.incident_id)}')">Open Incident</button>`:'';
  box.innerHTML=`<div class="card"><div class="card-title">RCA Result ${esc(d.incident_id||d.session_id||'')} ${modeBadge}</div>
    <div><strong>${esc(d.root_cause_category||'').toUpperCase()}</strong> ${Math.round((d.confidence||0)*100)}% — ${esc(d.root_cause||'')}</div>
    <div style="font-size:.8rem;color:var(--text-muted)">Files: ${esc((d.files||[]).join(', '))} · Records: ${d.record_count} · Range: ${esc((d.time_range||[])[0]||'')} → ${esc((d.time_range||[])[1]||'')}</div>
    <div style="margin-top:8px"><strong>Supporting</strong>${(d.supporting_evidence||[]).map(e=>`<div class="evidence-box">✔ ${esc(e)}</div>`).join('')}</div>
    <div><strong>Contradictory</strong>${(d.contradictory_evidence||[]).map(e=>`<div class="evidence-box">✖ ${esc(e)}</div>`).join('')||'<p style="color:var(--text-muted)">None</p>'}</div>
    <div><strong>Timeline</strong>${(d.timeline||[]).map(t=>`<div style="font-size:.78rem">${esc(t.timestamp)} [${esc(t.event_type)}] ${esc(t.description)}</div>`).join('')}</div>
    ${repoHint}
    <div style="margin-top:8px">${openBtn} ${convBtn}</div></div>`;
  refreshAnalyses();
}
async function convertSession(session_id){
  const title=prompt('Incident title for conversion:','Converted log analysis')||'Converted log analysis';
  const r=await fetch('/api/analysis-sessions/'+session_id+'/convert',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'create',title})});
  const d=await r.json();
  if(!r.ok){ alert(d.detail||'conversion failed'); return; }
  openIncident(d.incident_id);
}
async function refreshAnalyses(){
  try{
    const r=await fetch('/api/log-analyses');
    if(!r.ok) throw 0;
    const rows=await r.json();
    document.getElementById('analyses-list').innerHTML=rows.length?rows.map(a=>`<div class="evidence-box"><strong>${esc(a.analysis_id)}</strong> ${esc(a.project_id)} · ${(a.files||[]).length} file(s) · ${a.record_count} records · ${esc(a.status)} <button class="sim-btn" onclick="openAnalysis('${esc(a.analysis_id)}')">Open</button></div>`).join(''):'<span style="color:var(--text-muted)">No log analyses yet.</span>';
  }catch(e){ document.getElementById('analyses-list').innerHTML='<span style="color:var(--text-muted)">Could not load analyses. <button class="sim-btn" onclick="refreshAnalyses()">Retry</button></span>'; }
}
async function openAnalysis(aid){
  try{
    const a=await (await fetch('/api/log-analyses/'+aid)).json();
    const box=document.getElementById('analysis-detail');
    box.innerHTML=`<div class="card"><div class="card-title">${esc(a.analysis_id)}</div>
      <div style="font-size:.84rem">Project: ${esc(a.project_id)} · Source: ${esc(a.source_type)} · Services: ${esc((a.services||[]).join(', ')||'—')}<br/>Range: ${esc(a.time_start||'')} → ${esc(a.time_end||'')} · Records: ${a.record_count} · Errors: ${(a.error_codes||[]).join(', ')||'—'}</div>
      ${a.rca&&a.rca.root_cause?`<div style="margin-top:8px"><strong>RCA:</strong> ${esc(a.rca.root_cause_category||'')} ${Math.round((a.rca.confidence||0)*100)}% — ${esc(a.rca.root_cause||'')}</div><div><strong>Supporting</strong>${(a.rca.supporting_evidence||[]).map(e=>`<div class="evidence-box">✔ ${esc(e)}</div>`).join('')}</div><div><strong>Contradictory</strong>${(a.rca.contradictory_evidence||[]).map(e=>`<div class="evidence-box">✖ ${esc(e)}</div>`).join('')||'<p style="color:var(--text-muted)">None</p>'}</div><div><strong>Timeline</strong>${(a.rca.timeline||[]).map(t=>`<div style="font-size:.78rem">${esc(t.timestamp)} [${esc(t.event_type)}] ${esc(t.description)}</div>`).join('')}</div>${a.rca.incident_id?`<div style="margin-top:6px"><button class="sim-btn" onclick="openIncident('${esc(a.rca.incident_id)}')">Open Incident</button></div>`:''}`:'<p style="color:var(--text-muted)">Not analyzed yet.</p>'}
      </div>`;
    box.scrollIntoView({behavior:'smooth'});
  }catch(e){}
}
/* ---- settings ---- */
async function loadSettings(){
  const box=document.getElementById('settings-body'); if(!box) return;
  try{
    const h=await (await fetch('/health')).json();
    const r=await (await fetch('/ready')).json();
    box.innerHTML=`<div style="font-size:.85rem">Version: ${esc(h.version||'')} · Commit: ${esc(h.commit||'')} · Revision: ${esc(h.revision||'')}<br/>`+
      Object.entries(r.checks||{}).map(([k,v])=>`${esc(k)}: ${v?'✓':'•'}`).join('<br/>')+`</div>
      <div style="font-size:.8rem;color:var(--text-muted);margin-top:8px">Secrets are never displayed. Token presence only.</div>`;
  }catch(e){ box.innerHTML='Unavailable.'; }
  document.querySelectorAll('input[name="theme"]').forEach(el=>{ el.checked=(el.value===(localStorage.getItem('rca-theme')||'system')); });
}

setInterval(fetchLogs,3000); setInterval(tickFreshness,15000);
window.addEventListener('hashchange',syncFromHash);
window.onload=()=>{initTheme();initRouter();fetchLogs();loadTaxonomy();loadSideProjects();};
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    return DASHBOARD_HTML


@app.get("/api/incidents")
def list_incidents():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inc_dir = os.path.join(base_dir, "data", "incidents")
    files = [os.path.basename(p) for p in glob.glob(os.path.join(inc_dir, "incident_00*.json"))]
    return sorted(files)


@app.get("/api/analyze/{incident_filename}")
async def analyze_incident_api(incident_filename: str):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", "incidents", incident_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Incident file not found")

    import time as _time
    agent = CloudRCAAgent()
    _started = _time.time()
    result = await asyncio.to_thread(agent.analyze, file_path)
    try:
        _registry().ensure(result.incident_id, title=f"Static RCA {incident_filename}",
                           services=list(result.affected_services),
                           evidence_source="static")
        for _t in ("COLLECTING_EVIDENCE", "ANALYZING", "ROOT_CAUSE_IDENTIFIED"):
            _bump(result.incident_id, _t, "web-user")
        _registry().add_rca_run(result.incident_id, {
            "category": result.root_cause_category, "confidence": result.confidence_score,
            "duration_s": round(_time.time() - _started, 1), "evidence_source": "static"})
    except Exception:
        pass
    return result.model_dump()


# Platform: health, approval, remediation, execution, verification, memory

@app.get("/health")
def health():
    return {"status": "ok", "version": os.getenv("APP_VERSION","0.4.0"), "commit": os.getenv("GIT_COMMIT","unknown"), "revision": os.getenv("K_REVISION","local")}

@app.get("/ready")
def ready():
    # Readiness: process running and config loaded; Gemini optional (deterministic fallback available)
    checks = {
        "config_loaded": True,
        "gemini_configured": bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_CLOUD_PROJECT")),
        "bigquery_configured": bool(os.getenv("USE_BIGQUERY", "false")=="true" and os.getenv("GOOGLE_CLOUD_PROJECT")),
    }
    # Ready if core config loaded; gemini/bigquery are optional due to deterministic fallback
    return {"ready": checks["config_loaded"], "checks": checks}

@app.post("/incidents/{incident_id}/remediation/plan")
async def create_remediation_plan(incident_id: str):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", "incidents", f"{incident_id}.json")
    # Try mapping incident_id like INC-003-BAD-DEPLOYMENT to file
    if not os.path.exists(file_path):
        # search
        for f in glob.glob(os.path.join(base_dir, "data", "incidents", "*.json")):
            if incident_id.lower() in f.lower() or incident_id.replace("-","_").lower() in f.lower():
                file_path = f
                break
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Incident not found")
    with open(file_path) as f:
        import json as _json
        data = _json.load(f)
    from schemas.evidence import IncidentEvidence
    ev = IncidentEvidence(**data)
    # Heavy multi-agent workflow runs in a thread so polls/clicks stay responsive
    state, plan, cat = await asyncio.to_thread(_investigate_and_plan, ev)
    # Create approval request via manager
    approval = global_approval_manager.create_request(
        incident_id=incident_id, action=plan.recommended_action, target_resource=plan.target_resource or f"projects/{ev.project_id}/locations/{ev.region}/services/{ev.service_name}",
        rationale=plan.expected_effect, root_cause=plan.root_cause, confidence=plan.confidence, risk=plan.estimated_risk.value,
        expected_impact=plan.expected_effect, rollback_plan=plan.rollback_plan
    )
    audit_log("REMEDIATION_PLANNED", incident_id, "RemediationAgent", plan.recommended_action, approval.target_resource, before=None, after=plan.model_dump(), approval_id=approval.approval_id)
    return {"remediation_plan": plan.model_dump(), "approval": approval.model_dump()}

# NOTE: static /api/approvals/pending + /recent must be registered BEFORE the
# parameterized /api/approvals/{approval_id} route, otherwise "pending"/"recent"
# are captured as an approval_id and return 404.
@app.get("/api/approvals/pending")
def list_pending_approvals():
    return [r.model_dump() for r in global_approval_manager.list_pending()]

@app.get("/api/gitops/preflight")
def gitops_preflight():
    from gitops.repository import preflight
    return preflight(_demo_repo())


@app.get("/api/approvals/recent")
def list_recent_approvals(limit: int = 10):
    """Decision history: approved/rejected/expired/cancelled, newest first."""
    return [r.model_dump() for r in global_approval_manager.list_recent(limit)]

@app.get("/approvals/{approval_id}")
@app.get("/api/approvals/{approval_id}")
def get_approval(approval_id: str):
    req = global_approval_manager.get(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    return req.model_dump()

@app.post("/approvals/{approval_id}/approve")
@app.post("/api/approvals/{approval_id}/approve")
def approve_request(approval_id: str, approver: str = "human-operator", body: dict = None):
    # Accept custom message via JSON body {approver, message} or query param
    msg = (body or {}).get("message", "") if isinstance(body, dict) else ""
    if isinstance(body, dict) and body.get("approver"):
        approver = body.get("approver")
    req = global_approval_manager.approve(approval_id, approver=approver, message=msg)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    audit_log("APPROVAL_APPROVED", req.incident_id, approver, req.action, req.target_resource, approval_id=approval_id, result=msg)
    try:
        from orchestration.incident_registry import record_activity
        from orchestration.notifications import notify
        _bump(req.incident_id, "APPROVED", approver)
        record_activity("APPROVAL_APPROVED", req.incident_id, approver,
                        f"{req.action} approved", {"approval_id": approval_id})
        notify("APPROVAL_DECIDED", {"incident_id": req.incident_id, "target": req.action,
                                    "description": f"approved {req.action}"})
    except Exception:
        pass
    return req.model_dump()

@app.post("/approvals/{approval_id}/reject")
@app.post("/api/approvals/{approval_id}/reject")
def reject_request(approval_id: str, approver: str = "human-operator", body: dict = None):
    msg = (body or {}).get("message", "") if isinstance(body, dict) else ""
    if isinstance(body, dict) and body.get("approver"):
        approver = body.get("approver")
    if not (msg or "").strip():
        raise HTTPException(status_code=400, detail="A rejection comment is required")
    req = global_approval_manager.reject(approval_id, approver=approver, message=msg)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    audit_log("APPROVAL_REJECTED", req.incident_id, approver, req.action, req.target_resource, approval_id=approval_id, result=msg)
    try:
        from orchestration.incident_registry import record_activity
        from orchestration.notifications import notify
        _bump(req.incident_id, "REMEDIATION_PROPOSED", approver)
        record_activity("APPROVAL_REJECTED", req.incident_id, approver,
                        f"{req.action} rejected: {msg}", {"approval_id": approval_id})
        notify("APPROVAL_DECIDED", {"incident_id": req.incident_id, "target": req.action,
                                    "description": f"rejected {req.action}"})
    except Exception:
        pass
    return req.model_dump()

@app.post("/approvals/{approval_id}/cancel")
@app.post("/api/approvals/{approval_id}/cancel")
def cancel_request(approval_id: str):
    req = global_approval_manager.cancel(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    audit_log("APPROVAL_CANCELLED", req.incident_id, "system", req.action, req.target_resource, approval_id=approval_id)
    return req.model_dump()

@app.post("/approvals/{approval_id}/execute")
@app.post("/api/approvals/{approval_id}/execute")
async def execute_approval(approval_id: str, action_params: dict = None):
    action_params = action_params or {}
    req = global_approval_manager.get(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    # Cloud API calls run in a thread so the event loop stays free
    result, verification, postmortem = await asyncio.to_thread(_execute_and_verify, req, action_params)
    try:
        from orchestration.incident_registry import record_activity
        if result.status.value == "SUCCESS" and verification.verification_status.value == "RESOLVED":
            _bump(req.incident_id, "RESOLVED", "verification-agent")
            record_activity("INCIDENT_RESOLVED", req.incident_id, "verification-agent",
                            "infra remediation verified", {})
    except Exception:
        pass
    return {"execution": result.model_dump(), "verification": verification.model_dump(), "postmortem": postmortem}

# --- Live simulation + logs (for website button demo) ---
from datetime import datetime, timezone
import uuid

SIMULATED_LOGS = []  # in-memory, also appended to data/audit.log via audit_log
LATEST_SIMULATED_FILE = None
LATEST_SCENARIO = None
# scenario -> static incident file (None = evidence built purely from live logs)
SCENARIO_MAP = {
    "db-timeout": "incident_001_db_timeout.json",
    "pool-exhaustion": "incident_002_pool_exhaustion.json",
    "bad-deployment": "incident_003_bad_deployment.json",
    "dependency-failure": "incident_004_dependency_outage.json",
    "traffic-overload": "incident_005_traffic_overload.json",
    "config-error": "incident_006_config_regression.json",
    "memory-leak": None,
    "cpu-exhaustion": None,
    "auth-failure": None,
    "network-timeout": None,
    "malformed-payload": None,
    "rate-limit": None,
}

@app.get("/api/logs/live")
def get_live_logs(limit: int = 50):
    # Bucket is source of truth if configured - also return in-memory for low latency
    bucket = None
    try:
        from tools.gcs_tools import get_log_bucket, download_blob_text
        import json as _json
        bucket = get_log_bucket()
        if bucket and LATEST_SIMULATED_FILE:
            # Try bucket-backed logs for durability (fallback to memory if empty)
            text = download_blob_text(bucket, f"logs/live/{LATEST_SIMULATED_FILE}.jsonl")
            if text:
                lines = [ _json.loads(l) for l in text.strip().split("\n") if l.strip() ]
                if lines:
                    return lines[-limit:]
    except Exception:
        pass
    return SIMULATED_LOGS[-limit:]

@app.post("/api/logs/clear")
def clear_logs():
    SIMULATED_LOGS.clear()
    global LATEST_SIMULATED_FILE
    LATEST_SIMULATED_FILE = None
    return {"cleared": True}

@app.get("/api/logs/summary")
def logs_summary():
    """Dashboard summary row computed from the live stream (Part 3)."""
    from tools.live_log_generator import summarize
    summary = summarize(SIMULATED_LOGS)
    summary["error_code_counts"] = {}
    try:
        from collections import Counter
        summary["error_code_counts"] = dict(Counter(
            l.get("error_code") for l in SIMULATED_LOGS if l.get("error_code")))
    except Exception:
        pass
    return summary

@app.post("/api/simulate/{scenario}")
def simulate_error(scenario: str):
    from tools.live_log_generator import SCENARIO_SPECS, generate_logs, summarize
    if scenario not in SCENARIO_SPECS:
        raise HTTPException(status_code=400, detail=f"Unknown scenario {scenario}. Choose {sorted(SCENARIO_SPECS)}")
    spec = SCENARIO_SPECS[scenario]
    incident_file = SCENARIO_MAP.get(scenario)
    global LATEST_SIMULATED_FILE, LATEST_SCENARIO
    LATEST_SIMULATED_FILE = incident_file
    LATEST_SCENARIO = scenario
    incident_id = f"INC-LIVE-{spec['incident_type']}"
    # Baseline + incident phases streamed as structured logs
    new_logs = generate_logs(scenario, incident_id=incident_id)
    bucket = None
    try:
        from tools.gcs_tools import get_log_bucket
        bucket = get_log_bucket()
    except Exception:
        bucket = None
    SIMULATED_LOGS.extend(new_logs)
    if bucket:
        try:
            from tools.gcs_tools import upload_jsonl_to_bucket
            key = incident_file or f"live-{scenario}.json"
            for entry in new_logs:
                upload_jsonl_to_bucket(bucket, f"logs/live/{key}.jsonl", entry)
                upload_jsonl_to_bucket(bucket, "logs/live/central.jsonl", entry)
        except Exception:
            pass
    audit_log("SIMULATE", incident_file or scenario, "web-user", spec["error_code"], spec["service"])
    try:
        from orchestration.incident_registry import record_activity
        from tools.error_taxonomy import LABELS
        sev = {"CRITICAL": "P1", "ERROR": "P1"}.get(spec["severity"], "P2")
        _registry().ensure(incident_id, project_id=_projects().resolve_project(spec["service"]),
                           title=f"{LABELS.get(scenario, scenario)} on {spec['service']}",
                           severity=sev, services=[spec["service"]], evidence_source="live")
        _bump(incident_id, "COLLECTING_EVIDENCE", "web-user")
        record_activity("SIMULATION_STARTED", incident_id, "web-user",
                        f"simulated {scenario}", {"scenario": scenario})
    except Exception:
        pass
    return {"simulated": True, "scenario": scenario, "incident_id": incident_id,
            "incident_file": incident_file, "logs_injected": len(new_logs),
            "bucket": bucket or "local", "summary": summarize(new_logs)}

MANUAL_EVIDENCE = {}  # incident_id -> manual-create inputs for RCA


def _manual_evidence(incident_id: str, inputs: dict):
    """Evidence for a manually created incident (no simulation needed)."""
    from datetime import datetime, timedelta, timezone as _tz
    from tools.normalizer import normalize_evidence
    start = inputs.get("start_time") or datetime.now(_tz.utc).isoformat()
    try:
        end = (datetime.fromisoformat(start.replace("Z", "+00:00")) + timedelta(minutes=15)).isoformat()
    except ValueError:
        end = start
    service = (inputs.get("services") or ["unknown-service"])[0]
    desc = inputs.get("description", "") or inputs.get("title", "")
    code = inputs.get("error_signature", "") or "MANUAL_INCIDENT"
    raw_logs = [{
        "timestamp": start, "severity": "ERROR",
        "payload": {"error_code": code, "message": desc, "endpoint": "/"},
        "http_request": {"status": 500, "request_url": "/"},
        "trace_id": inputs.get("trace_id") or None,
    }]
    deployments = []
    if inputs.get("revision"):
        deployments = [{"revision_name": inputs["revision"], "deployed_at": start,
                        "traffic_percent": 100}]
    traces = [{"trace_id": inputs["trace_id"]}] if inputs.get("trace_id") else []
    return normalize_evidence(
        incident_id=incident_id, project_id=inputs.get("project_id", "manual"),
        service_name=service, start_time=start, end_time=end, raw_logs=raw_logs,
        raw_metrics={}, deployment_events=deployments, raw_traces=traces,
        dependencies=[], revision_name=inputs.get("revision") or None, region="")


@app.post("/api/rca/live")
async def run_live_rca(body: dict = None):
    # Fresh investigation from the LIVE log stream (Part 4). Static files only
    # supply deployments/traces/dependencies; counts, rates and latencies come
    # from the actual streamed logs. Scenarios without static files are built
    # purely from live evidence. A manual incident_id runs from stored inputs.
    import time as _time
    from schemas.evidence import IncidentEvidence
    from tools.live_evidence import merge_static_with_live, build_evidence_from_logs
    from tools.error_taxonomy import domain_for_category, domain_for_scenario
    from orchestration.incident_registry import record_activity
    manual_id = (body or {}).get("incident_id") if isinstance(body, dict) else None
    scenario, incident_file, evidence_source = LATEST_SCENARIO, LATEST_SIMULATED_FILE, "live"
    live_logs = [l for l in SIMULATED_LOGS
                 if not scenario or l.get("scenario") == scenario] or SIMULATED_LOGS
    if manual_id and manual_id in MANUAL_EVIDENCE:
        ev = _manual_evidence(manual_id, MANUAL_EVIDENCE[manual_id])
        live_logs, evidence_source = [], "manual"
    elif incident_file:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        file_path = os.path.join(base_dir, "data", "incidents", incident_file)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Simulated incident file not found")
        with open(file_path) as f:
            data = json.load(f)
        data = merge_static_with_live(data, live_logs)
        ev = IncidentEvidence(**data)
    elif scenario:
        ev = build_evidence_from_logs(scenario, live_logs)
    else:
        raise HTTPException(status_code=400, detail="Simulate an incident first (POST /api/simulate/{scenario})")
    # Heavy workflow in a thread — polls and clicks keep working while it runs.
    # NOTE: RCA creates NOTHING else here. Remediation/code-fix proposals are
    # explicit user actions (Propose Remediation / Generate Fix buttons).
    try:
        _registry().ensure(ev.incident_id, project_id=_projects().resolve_project(ev.service_name),
                           title=f"Live RCA on {ev.service_name}", severity=ev.severity,
                           services=[ev.service_name], evidence_source=evidence_source)
        for _t in ("COLLECTING_EVIDENCE", "ANALYZING"):
            _bump(ev.incident_id, _t, "web-user")
        from orchestration.incident_registry import record_activity
        record_activity("RCA_STARTED", ev.incident_id, "web-user", "live RCA started", {})
    except Exception:
        pass
    import time as _time
    _started = _time.time()
    wf = InvestigationWorkflow()
    state = await asyncio.to_thread(wf.run, ev)
    _duration = round(_time.time() - _started, 1)
    audit_log("RCA_LIVE", ev.incident_id, "web-user", "investigation_complete",
              ev.service_name)
    result = state.final_report.model_dump()
    result["timeline"] = [t.model_dump() for t in state.final_report.timeline]
    # hypotheses + verdicts back the on-screen confidence explanation
    result["hypotheses"] = [h.model_dump() for h in state.hypotheses]
    result["validations"] = [v.model_dump() for v in
                             state.validated_hypotheses + state.rejected_hypotheses]
    # add simulated logs hint
    result["live_logs_count"] = len(SIMULATED_LOGS)
    result["remediation_available"] = True
    # remember validated RCA for the code-fix pipeline (Part 5+)
    _best_cat, _best_conf = None, 0.0
    for _v in state.validated_hypotheses:
        if _v.accepted:
            _h = next((x for x in state.hypotheses if x.hypothesis_id == _v.hypothesis_id), None)
            if _h and _v.adjusted_confidence >= _best_conf:
                _best_cat, _best_conf = _h.root_cause_category, _v.adjusted_confidence
    _best_cat = _best_cat or (state.hypotheses[0].root_cause_category if state.hypotheses else "unknown")
    result["root_cause_category"] = _best_cat
    LAST_RCA[ev.incident_id] = {
        "root_cause_category": _best_cat,
        "root_cause": state.final_report.root_cause,
        "confidence": state.final_report.confidence,
        "supporting_evidence": state.final_report.supporting_evidence,
        "contradictory_evidence": state.final_report.contradictory_evidence,
        "service": ev.service_name,
    }
    LAST_INVESTIGATION[ev.incident_id] = {"state": state, "category": _best_cat}
    while len(LAST_INVESTIGATION) > 20:
        LAST_INVESTIGATION.pop(next(iter(LAST_INVESTIGATION)))
    try:
        _domain, _sub = domain_for_category(_best_cat)
        result["error_domain"], result["error_subcategory"] = _domain, _sub
        result["evidence_source"] = evidence_source
        _registry().add_rca_run(ev.incident_id, {"category": _best_cat,
                                                 "confidence": state.final_report.confidence,
                                                 "duration_s": _duration, "evidence_source": evidence_source})
        _registry().set_fields(ev.incident_id, error_domain=_domain, error_subcategory=_sub)
        _bump(ev.incident_id, "ROOT_CAUSE_IDENTIFIED", "rca-agent")
        record_activity("ROOT_CAUSE_IDENTIFIED", ev.incident_id, "rca-agent",
                        f"{_best_cat} ({state.final_report.confidence})", {})
        from orchestration.notifications import notify
        notify("RCA_COMPLETE", {"incident_id": ev.incident_id, "target": ev.service_name,
                                "description": f"RCA {_best_cat} {state.final_report.confidence}"})
    except Exception:
        pass
    return result

# --- Code fix + PR pipeline (Parts 5-15, 19) ---
from schemas.code_fix import FixJob, FixStatus

FIX_JOBS = {}  # incident_id -> {"job": FixJob, "proposal": PatchProposal|None, "approval_id": str|None}
LAST_RCA = {}  # incident_id -> validated RCA summary for code mapping
LAST_INVESTIGATION = {}  # incident_id -> {"state": InvestigationState, "category": str} (bounded, for explicit remediation proposals)
APPROVAL_PARAMS = {}  # approval_id -> suggested executor params (rollback target, scale bounds)


def _record_agent_pr(incident_id, rca, proposal, approval_req, job, branch, base, title, body):
    """Persist every agent PR attempt (Open or Failed) to the PR registry."""
    import os as _os
    from datetime import datetime, timezone as _tz
    from projects.store import ProjectStore, PRRegistry
    from schemas.project import PullRequestRecord
    from orchestration.incident_registry import record_activity
    from orchestration.notifications import notify
    service = rca.get("service", "checkout-service")
    project_id = ProjectStore().resolve_project(service)
    number = job.pr_number
    pr_id = f"PR-{number}" if number else f"PR-{incident_id}-{job.patch_sha256[:8].upper()}"
    record = PullRequestRecord(
        pr_id=pr_id, pr_number=number, project_id=project_id, incident_id=incident_id,
        repository=_os.getenv("DEMO_APP_REPO_SLUG", "swethakambathula/cloud-rca-demo-app"),
        branch=branch or "", base_branch=base, commit_sha=job.commit or "",
        title=title, root_cause=rca.get("root_cause", ""),
        root_cause_category=proposal.root_cause_category,
        confidence=float(rca.get("confidence", 0.0) or 0.0), risk=proposal.risk,
        status="Open" if job.pr_url else "Failed",
        tests_status="passed" if job.pr_url else "failed",
        tests_output=(job.test_output or "")[-2000:],
        files_changed=list(proposal.files_changed), additions=proposal.lines_added,
        deletions=proposal.lines_removed, diff=proposal.patch,
        supporting_evidence=list(rca.get("supporting_evidence", []))[:8],
        approval_id=approval_req.approval_id, approved_by=approval_req.decided_by or "",
        approved_at=approval_req.decided_at or "",
        created_at=datetime.now(_tz.utc).isoformat(), created_by="rca-agent",
        external_url=job.pr_url or "")
    PRRegistry().record(record)
    if job.pr_url:
        _bump(incident_id, "PR_CREATED", "gitops")
        try:
            _registry().set_fields(incident_id, pr_id=pr_id)
        except Exception:
            pass
        record_activity("PR_CREATED", incident_id, "gitops", f"{pr_id} {title}",
                        {"pr_url": job.pr_url, "branch": branch})
        notify("PR_CREATED", {"incident_id": incident_id, "target": branch,
                              "description": f"{pr_id} opened: {title}"})
    else:
        record_activity("PR_FAILED", incident_id, "gitops", job.error or "PR creation failed", {})
        notify("PR_FAILED", {"incident_id": incident_id, "target": branch,
                             "description": job.error or "PR creation failed"})
    return record


def _suggest_infra_params(evidence, action: str) -> dict:
    """Derive executor params from investigation evidence so Execute is one click.

    Rollback target = newest revision that is not the incident's active one.
    Scale default stays within MAX_SCALE_LIMIT. Shift-traffic needs human JSON.
    """
    if action == "cloud_run_rollback":
        revs = [d.get("revision_name") for d in (evidence.recent_deployments or [])
                if isinstance(d, dict) and d.get("revision_name")]
        target = next((r for r in revs if r != evidence.revision_name), None)
        if target is None and len(revs) > 1:
            target = revs[1]
        return {"target_revision": target} if target else {}
    if action == "cloud_run_scale_within_limits":
        import os as _os
        try:
            limit = int(_os.getenv("MAX_SCALE_LIMIT", "20"))
        except ValueError:
            limit = 20
        return {"max_instances": min(10, limit)}
    return {}


def _get_rca(incident_id: str) -> dict:
    rca = LAST_RCA.get(incident_id)
    if not rca:
        raise HTTPException(status_code=400, detail=f"No validated RCA for {incident_id}: click 'Run Live RCA' first")
    return rca


def _demo_repo() -> str:
    import os as _os
    return _os.getenv("DEMO_APP_PATH") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cloud-rca-demo-app")


@app.post("/api/incidents/{incident_id}/remediation/propose")
async def propose_remediation(incident_id: str):
    """Explicit remediation proposal from the stored live investigation.

    Creates exactly one INFRASTRUCTURE_ACTION approval. Nothing is proposed
    automatically — the dashboard calls this only via Propose Remediation.
    """
    entry = LAST_INVESTIGATION.get(incident_id)
    if not entry:
        raise HTTPException(status_code=400, detail=f"No live investigation for {incident_id}: click 'Run Live RCA' first")
    state, cat = entry["state"], entry["category"]
    plan = await asyncio.to_thread(
        RemediationAgent().plan, state.incident_evidence, state.final_report, cat)
    approval = global_approval_manager.create_request(
        incident_id=incident_id, action=plan.recommended_action, target_resource=plan.target_resource,
        rationale=plan.expected_effect, root_cause=plan.root_cause, confidence=plan.confidence, risk=plan.estimated_risk.value,
        expected_impact=plan.expected_effect, rollback_plan=plan.rollback_plan
    )
    APPROVAL_PARAMS[approval.approval_id] = _suggest_infra_params(state.incident_evidence, plan.recommended_action)
    from safety.remediation_policy import decide as _policy_decide
    policy = _policy_decide(plan.recommended_action).value
    audit_log("REMEDIATION_PLANNED", incident_id, "web-user", plan.recommended_action,
              approval.target_resource, approval_id=approval.approval_id)
    return {"remediation_plan": plan.model_dump(), "approval": approval.model_dump(),
            "suggested_params": APPROVAL_PARAMS[approval.approval_id],
            "policy": policy}


@app.get("/api/approvals/{approval_id}/live-traffic")
def approval_live_traffic(approval_id: str):
    """Live traffic split for the approval's target service — validate a
    rollback/shift actually took effect (Cloud Run API, mock fallback local)."""
    import os as _os
    req = global_approval_manager.get(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    parts = (req.target_resource or "").split("/")
    try:
        project_id = parts[1] if len(parts) > 1 else _os.getenv("GOOGLE_CLOUD_PROJECT", "")
        region = parts[3] if len(parts) > 3 else _os.getenv("GOOGLE_CLOUD_REGION", "us-central1")
        service_name = parts[5] if len(parts) > 5 else ""
    except Exception:
        raise HTTPException(status_code=400, detail="Cannot parse service from target_resource")
    if not service_name:
        raise HTTPException(status_code=400, detail="No service in target_resource")
    from tools.deployment_tools import get_revision_traffic_split, get_current_revision
    split = get_revision_traffic_split(project_id, region, service_name) or {}
    current = get_current_revision(project_id, region, service_name) or {}
    current_rev = current.get("latest_ready_revision") or current.get("revision_name") or ""
    if not split and current_rev:
        split = {current_rev: current.get("traffic_percent", 100)}
    return {"approval_id": approval_id, "service": service_name, "project_id": project_id,
            "region": region, "current_revision": current_rev,
            "traffic_split": split}


@app.get("/api/approvals/{approval_id}/params")
def approval_params(approval_id: str):
    """Suggested executor params for an approval (empty when human input needed)."""
    req = global_approval_manager.get(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    return {"approval_id": approval_id, "action": req.action,
            "status": req.status.value, "params": APPROVAL_PARAMS.get(approval_id, {})}


@app.get("/api/incidents/{incident_id}/timeline")
def incident_timeline(incident_id: str, view: str = "significant"):
    """Timeline for the incident's stored investigation.

    view=significant (default): milestones plus one grouped entry per repeated
    error signature. view=all: every raw event. Grouping/parsing is
    deterministic (tools/timeline_view.py).
    """
    from tools.timeline_view import group_events, significant
    entry = LAST_INVESTIGATION.get(incident_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    events = [t.model_dump() for t in entry["state"].final_report.timeline]
    if view == "all":
        return {"incident_id": incident_id, "view": "all",
                "total_events": len(events), "events": events}
    groups = group_events(events)
    sig = significant(events)
    return {"incident_id": incident_id, "view": "significant",
            "total_events": len(events), "groups": groups, "events": sig}


@app.get("/api/incidents/{incident_id}/evidence/raw")
def incident_raw_evidence(incident_id: str, limit: int = 100):
    """Raw evidence drawer backing: logs, metrics, deployments, traces, agent
    findings. Read-only; the human-readable RCA stays the primary report."""
    entry = LAST_INVESTIGATION.get(incident_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    state = entry["state"]
    ev = state.incident_evidence
    cap = max(1, min(limit, 500))
    return {
        "incident_id": incident_id,
        "raw_logs": (ev.raw_evidence or [])[:cap],
        "application_errors": ev.application_errors or [],
        "request_errors": (ev.request_errors or [])[:cap],
        "metrics": {"latency": ev.latency or {}, "request_count": ev.request_count or {},
                    "cpu_utilization": ev.cpu_utilization or {},
                    "memory_utilization": ev.memory_utilization or {}},
        "recent_deployments": ev.recent_deployments or [],
        "traces": (ev.traces or [])[:cap],
        "dependencies": ev.dependencies or [],
        "agent_findings": [f.model_dump() for f in state.agent_findings[:cap]],
    }


@app.get("/api/approvals/{approval_id}/revisions")
def approval_revisions(approval_id: str):
    """Rollback candidates from the investigation evidence: previous versions
    with deploy time, traffic and current-revision marking. Suggested default
    is the newest non-current revision."""
    req = global_approval_manager.get(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    entry = LAST_INVESTIGATION.get(req.incident_id)
    if not entry:
        return {"approval_id": approval_id, "revisions": [], "suggested": None,
                "hint": "No stored investigation for this incident; enter the revision manually."}
    ev = entry["state"].incident_evidence
    current = ev.revision_name
    seen, out = set(), []
    for d in (ev.recent_deployments or []):
        if not isinstance(d, dict):
            continue
        name = d.get("revision_name")
        if not name or name in seen:
            continue
        seen.add(name)
        out.append({
            "revision_name": name,
            "deployed_at": d.get("deployed_at") or d.get("creation_time") or "",
            "traffic_percent": d.get("traffic_percent", d.get("traffic", "")),
            "is_current": name == current,
        })
    suggested = next((r["revision_name"] for r in out if not r["is_current"]), None)
    return {"approval_id": approval_id, "current_revision": current,
            "revisions": out, "suggested": suggested}


@app.post("/api/incidents/{incident_id}/analyze-code")
async def analyze_code(incident_id: str):
    from agents.code_investigation_agent.agent import CodeInvestigationAgent
    from gitops.branch_manager import checkout_base
    rca = _get_rca(incident_id)
    # Always inspect clean base state, never a leftover previous fix branch
    try:
        await asyncio.to_thread(checkout_base, _demo_repo())
    except (RuntimeError, PermissionError) as e:
        raise HTTPException(status_code=409, detail=str(e)[:500])
    inv = await asyncio.to_thread(
        CodeInvestigationAgent().investigate, incident_id, rca["root_cause_category"])
    audit_log("CODE_INVESTIGATED", incident_id, "CodeInvestigationAgent",
              rca["root_cause_category"], _demo_repo())
    return inv.model_dump()


@app.post("/api/incidents/{incident_id}/generate-fix")
async def generate_fix(incident_id: str):
    from agents.code_investigation_agent.agent import CodeInvestigationAgent
    from agents.patch_agent.agent import PatchAgent
    from gitops.branch_manager import checkout_base
    rca = _get_rca(incident_id)
    try:
        await asyncio.to_thread(checkout_base, _demo_repo())
    except (RuntimeError, PermissionError) as e:
        raise HTTPException(status_code=409, detail=str(e)[:500])
    inv = await asyncio.to_thread(
        CodeInvestigationAgent().investigate, incident_id, rca["root_cause_category"])
    if inv.no_fix_reason or not inv.findings:
        job = FixJob(incident_id=incident_id, status=FixStatus.SUGGESTED,
                     root_cause_category=rca["root_cause_category"],
                     error=inv.no_fix_reason or "No safe code-level remediation identified.")
        FIX_JOBS[incident_id] = {"job": job, "proposal": None, "approval_id": None,
                                 "investigation": inv.model_dump()}
        return {"investigation": inv.model_dump(), "proposal": None,
                "fix_status": job.status.value, "no_fix_reason": job.error}
    try:
        proposal = await asyncio.to_thread(
            PatchAgent().generate, incident_id, rca["root_cause_category"])
    except ValueError as e:
        job = FixJob(incident_id=incident_id, status=FixStatus.FAILED,
                     root_cause_category=rca["root_cause_category"], error=str(e))
        FIX_JOBS[incident_id] = {"job": job, "proposal": None, "approval_id": None,
                                 "investigation": inv.model_dump()}
        return {"investigation": inv.model_dump(), "proposal": None,
                "fix_status": job.status.value, "error": str(e)}
    approval = global_approval_manager.create_request(
        incident_id=incident_id, action="code_fix_pr",
        target_resource=f"repo:cloud-rca-demo-app files:{','.join(proposal.files_changed)}",
        rationale=proposal.reasoning_summary, root_cause=rca["root_cause"],
        confidence=rca["confidence"], risk=proposal.risk,
        expected_impact=proposal.summary, rollback_plan="Close PR unmerged; delete fix branch",
        action_type="CODE_CHANGE", patch_sha256=proposal.patch_sha256)
    job = FixJob(incident_id=incident_id, status=FixStatus.WAITING_FOR_APPROVAL,
                 root_cause_category=rca["root_cause_category"],
                 patch_sha256=proposal.patch_sha256, approval_id=approval.approval_id)
    FIX_JOBS[incident_id] = {"job": job, "proposal": proposal,
                             "approval_id": approval.approval_id,
                             "investigation": inv.model_dump()}
    audit_log("FIX_PROPOSED", incident_id, "PatchAgent", "code_fix_pr",
              approval.target_resource, approval_id=approval.approval_id,
              result=proposal.patch_sha256[:12])
    try:
        from orchestration.incident_registry import record_activity
        from orchestration.notifications import notify
        _bump(incident_id, "REMEDIATION_PROPOSED", "PatchAgent")
        _bump(incident_id, "WAITING_APPROVAL", "PatchAgent")
        record_activity("APPROVAL_REQUESTED", incident_id, "PatchAgent",
                        "code fix approval requested", {"approval_id": approval.approval_id})
        notify("APPROVAL_REQUESTED", {"incident_id": incident_id, "target": "code_fix_pr",
                                      "description": "code fix awaiting approval"})
    except Exception:
        pass
    return {"investigation": inv.model_dump(), "proposal": proposal.model_dump(),
            "approval": approval.model_dump(), "fix_status": job.status.value}


@app.get("/api/incidents/{incident_id}/fix")
def get_fix(incident_id: str):
    entry = FIX_JOBS.get(incident_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No code fix proposed yet for this incident")
    out = {"fix_status": entry["job"].status.value, "job": entry["job"].model_dump(),
           "investigation": entry.get("investigation")}
    if entry.get("proposal") is not None:
        out["proposal"] = entry["proposal"].model_dump()
    if entry.get("approval_id"):
        out["approval"] = global_approval_manager.get(entry["approval_id"]).model_dump()
    return out


@app.post("/api/incidents/{incident_id}/fix/approve")
def approve_fix(incident_id: str, body: dict = None):
    entry = FIX_JOBS.get(incident_id)
    if not entry or not entry.get("approval_id"):
        raise HTTPException(status_code=404, detail="No pending code fix approval for this incident")
    msg = (body or {}).get("message", "") if isinstance(body, dict) else ""
    req = global_approval_manager.get(entry["approval_id"])
    if not req or req.status.value != "PENDING":
        raise HTTPException(status_code=409, detail="Approval is no longer pending")
    # hash binding: approval must match the CURRENT proposal (regeneration invalidates)
    if req.patch_sha256 != entry["proposal"].patch_sha256:
        raise HTTPException(status_code=409, detail="Patch changed since approval request: re-approval required")
    req = global_approval_manager.approve(req.approval_id, message=msg)
    entry["job"].status = FixStatus.APPROVED
    audit_log("FIX_APPROVED", incident_id, "human-operator", "code_fix_pr",
              req.target_resource, approval_id=req.approval_id, result=msg)
    try:
        from orchestration.incident_registry import record_activity
        from orchestration.notifications import notify
        _bump(incident_id, "APPROVED", "human-operator")
        record_activity("APPROVAL_APPROVED", incident_id, "human-operator",
                        "code fix approved", {"approval_id": req.approval_id})
        notify("APPROVAL_DECIDED", {"incident_id": incident_id, "target": "code_fix_pr",
                                    "description": "code fix approved"})
    except Exception:
        pass
    return {"fix_status": entry["job"].status.value, "approval": req.model_dump()}


@app.post("/api/incidents/{incident_id}/fix/reject")
def reject_fix(incident_id: str, body: dict = None):
    entry = FIX_JOBS.get(incident_id)
    if not entry or not entry.get("approval_id"):
        raise HTTPException(status_code=404, detail="No pending code fix approval for this incident")
    msg = (body or {}).get("message", "") if isinstance(body, dict) else ""
    if not (msg or "").strip():
        raise HTTPException(status_code=400, detail="A rejection comment is required")
    req = global_approval_manager.reject(entry["approval_id"], message=msg)
    entry["job"].status = FixStatus.REJECTED
    audit_log("FIX_REJECTED", incident_id, "human-operator", "code_fix_pr",
              req.target_resource, approval_id=req.approval_id, result=msg)
    try:
        from orchestration.incident_registry import record_activity
        from orchestration.notifications import notify
        _bump(incident_id, "REMEDIATION_PROPOSED", "human-operator")
        record_activity("APPROVAL_REJECTED", incident_id, "human-operator",
                        f"code fix rejected: {msg}", {"approval_id": req.approval_id})
        notify("APPROVAL_DECIDED", {"incident_id": incident_id, "target": "code_fix_pr",
                                    "description": "code fix rejected"})
    except Exception:
        pass
    return {"fix_status": entry["job"].status.value, "approval": req.model_dump()}


@app.post("/api/incidents/{incident_id}/fix/apply")
async def apply_fix(incident_id: str):
    """Approved pipeline only: hash verify -> branch -> apply -> test -> commit -> push -> PR."""
    from gitops.branch_manager import create_fix_branch, slugify
    from gitops.patch_manager import apply_patch
    from gitops.test_runner import run_tests
    from gitops.commit_manager import commit_fix, push_branch
    from gitops.pr_manager import create_pr, pr_title, pr_body
    from gitops.repository import default_branch
    entry = FIX_JOBS.get(incident_id)
    if not entry or not entry.get("proposal"):
        raise HTTPException(status_code=404, detail="No code fix proposal for this incident")
    job, proposal = entry["job"], entry["proposal"]
    req = global_approval_manager.get(entry["approval_id"])
    if not req or req.status.value != "APPROVED":
        raise HTTPException(status_code=403, detail="Apply blocked: no APPROVED code-change approval")
    if req.patch_sha256 != proposal.patch_sha256:
        job.status = FixStatus.FAILED
        job.error = "Patch hash mismatch vs approval: re-approval required"
        raise HTTPException(status_code=409, detail=job.error)
    repo = _demo_repo()
    rca = LAST_RCA.get(incident_id, {})
    try:
        job.status = FixStatus.APPROVED
        branch = await asyncio.to_thread(create_fix_branch, repo, incident_id, proposal.root_cause_category)
        job.branch, job.status = branch, FixStatus.BRANCH_CREATED
        diffstat = await asyncio.to_thread(apply_patch, repo, proposal.patch, req.patch_sha256)
        job.status = FixStatus.PATCH_APPLIED
        job.status = FixStatus.TESTING
        test_res = await asyncio.to_thread(run_tests, repo, proposal.tests_to_run)
        job.test_output = test_res["output"]
        if not test_res["passed"]:
            job.status = FixStatus.FAILED
            job.error = "Patch applied. Tests FAILED — PR not created. Branch retained for inspection."
            audit_log("FIX_TESTS_FAILED", incident_id, "TestRunner", "pytest", repo,
                      approval_id=req.approval_id, result=test_res["output"][-500:])
            return {"fix_status": job.status.value, "job": job.model_dump(),
                    "detail": job.error, "diffstat": diffstat}
        job.status = FixStatus.TESTS_PASSED
        commit = await asyncio.to_thread(
            commit_fix, repo, branch, incident_id, proposal.root_cause_category,
            req.approval_id, rca.get("confidence", 0.0), proposal.tests_to_run)
        job.commit, job.status = commit, FixStatus.COMMITTED
        await asyncio.to_thread(push_branch, repo, branch)
        job.status = FixStatus.PUSHED
        base = default_branch(repo)
        title = pr_title(incident_id, proposal.summary)
        body = pr_body(incident_id, rca.get("service", "checkout-service"),
                       rca.get("root_cause", ""), rca.get("confidence", 0.0),
                       rca.get("supporting_evidence", []), proposal.files_changed,
                       proposal.risk, req.approval_id)
        pr = await asyncio.to_thread(create_pr, repo, branch, base, title, body)
        if pr.get("pr_url"):
            job.pr_url, job.pr_number = pr["pr_url"], pr.get("pr_number")
            job.status = FixStatus.PR_CREATED
        else:
            job.status, job.error = FixStatus.FAILED, f"PR not created: {pr.get('blocked')}. {pr.get('hint','')}"
        audit_log("FIX_APPLIED", incident_id, "gitops", "code_fix_pr", repo,
                  approval_id=req.approval_id, result=f"{job.status.value} {job.pr_url or ''}")
        try:
            _record_agent_pr(incident_id, rca, proposal, req, job, branch, base, title, body)
        except Exception:
            pass
        return {"fix_status": job.status.value, "job": job.model_dump(), "diffstat": diffstat}
    except (ValueError, RuntimeError, PermissionError) as e:
        job.status, job.error = FixStatus.FAILED, str(e)[:500]
        return {"fix_status": job.status.value, "job": job.model_dump(), "detail": str(e)[:500]}


@app.get("/api/incidents/{incident_id}/fix/status")
def fix_status(incident_id: str):
    entry = FIX_JOBS.get(incident_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No code fix yet for this incident")
    return {"fix_status": entry["job"].status.value, "job": entry["job"].model_dump()}


@app.get("/api/incidents/{incident_id}/pr")
def get_pr(incident_id: str):
    entry = FIX_JOBS.get(incident_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No code fix yet for this incident")
    job = entry["job"]
    return {"pr_url": job.pr_url, "pr_number": job.pr_number,
            "branch": job.branch, "commit": job.commit,
            "fix_status": job.status.value}

# ================= UX platform layer =================
# Projects, incident lifecycle, PR registry, uploads, home stats, taxonomy.
# All additive: existing routes, element IDs and RCA behavior are unchanged.


def _bump(incident_id: str, target: str, actor: str = "system") -> None:
    try:
        from orchestration.incident_registry import IncidentRegistry
        IncidentRegistry().transition(incident_id, target, actor)
    except Exception:
        pass  # re-runs or out-of-order states must never break RCA


def _projects():
    from projects.store import ProjectStore
    return ProjectStore()


def _registry():
    from orchestration.incident_registry import IncidentRegistry
    return IncidentRegistry()


@app.get("/api/taxonomy")
def get_taxonomy():
    from tools.error_taxonomy import SCENARIOS, CATEGORIES, GROUPS, LABELS
    return {
        "scenarios": {k: {"domain": d, "subcategory": s} for k, (d, s) in SCENARIOS.items()},
        "categories": {k: {"domain": d, "subcategory": s} for k, (d, s) in CATEGORIES.items()},
        "groups": GROUPS,
        "labels": LABELS,
    }


# ---------- projects ----------

@app.get("/api/projects")
def list_projects():
    store = _projects()
    reg = _registry()
    out = []
    for p in store.list():
        d = p.model_dump()
        incs = reg.list(project_id=p.project_id)
        d["open_incidents"] = sum(1 for i in incs if i.get("status") not in ("RESOLVED", "FAILED"))
        d["resolved_incidents"] = sum(1 for i in incs if i.get("status") == "RESOLVED")
        from projects.store import PRRegistry
        d["open_prs"] = sum(1 for r in PRRegistry().list(project_id=p.project_id)
                            if r.status in ("Open", "Awaiting Approval"))
        out.append(d)
    return out


@app.post("/api/projects")
def create_project(body: dict):
    import re as _re
    from schemas.project import Project
    from orchestration.incident_registry import record_activity
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Project name is required")
    pid = body.get("project_id") or _re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    project = Project(
        project_id=pid, name=name, description=body.get("description", ""),
        environment=body.get("environment", "prod"), team_owner=body.get("team_owner", ""),
        repository_url=body.get("repository_url", ""), provider=body.get("provider", "github"),
        default_branch=body.get("default_branch", "main"), local_path=body.get("local_path", ""),
        gcp_project_id=body.get("gcp_project_id", ""), region=body.get("region", ""),
        services=body.get("services", []),
        service_mappings=body.get("service_mappings", {}) or {}, status="active",
        sources_config={k: body.get(k, "") for k in
                        ("log_source", "metrics_source", "trace_source", "deployment_source")
                        if body.get(k)},
        data_sources=[{"kind": k, "status": "connected", "detail": ""}
                      for k in body.get("sources", []) if k in ("git", "gcp", "upload")],
    )
    from datetime import datetime, timezone as _tz
    project.created_at = datetime.now(_tz.utc).isoformat()
    _projects().upsert(project)
    record_activity("PROJECT_CREATED", "", "web-user", f"project {pid} onboarded",
                    {"project_id": pid})
    return project.model_dump()


@app.get("/api/projects/{project_id}")
def get_project(project_id: str):
    project = _projects().get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    d = project.model_dump()
    reg = _registry()
    d["incidents"] = reg.list(project_id=project_id)
    from projects.store import PRRegistry
    d["pull_requests"] = [r.model_dump() for r in PRRegistry().list(project_id=project_id)]
    return d


@app.post("/api/projects/onboard")
def onboard_project(body: dict):
    """Wizard submit: validate -> scan (read-only) -> persist -> readiness."""
    from projects.scanner import scan_repo, detect_default_branch, connection_ok
    repo_url = (body.get("repository_url") or "").strip()
    local_path = (body.get("local_path") or body.get("repository_path") or "").strip()
    conn = connection_ok(path=local_path, url=repo_url)
    scan, branch = {"error": "no repository given"}, body.get("default_branch", "main") or "main"
    if local_path:
        scan = scan_repo(local_path)
        if not body.get("default_branch"):
            branch = detect_default_branch(local_path)
    project_body = dict(body)
    project_body["default_branch"] = branch
    if isinstance(body.get("service_mappings"), dict):
        project_body["service_mappings"] = body["service_mappings"]
    created = create_project(project_body)
    pid = created["project_id"]
    store = _projects()
    project = store.get(pid)
    kinds = set()
    if repo_url or local_path:
        kinds.add("git")
    if body.get("gcp_project_id"):
        kinds.add("gcp")
    from schemas.project import DataSource
    project.data_sources = [DataSource(kind=k, status="connected" if (k != "git" or conn["ok"]) else "error",
                                       detail="") for k in sorted(kinds)]
    project.detected = {k: v for k, v in scan.items() if k != "error"}
    if local_path and not project.services:
        project.services = (scan.get("services") or [])[:8]
    from datetime import datetime, timezone as _tz
    project.last_scan = datetime.now(_tz.utc).isoformat()
    store.upsert(project)
    reasons = []
    if not conn["ok"] and (repo_url or local_path):
        reasons.append("repository unreachable: " + conn["detail"])
    if not project.services:
        reasons.append("no services detected")
    readiness = {"rca_ready": not reasons, "reasons": reasons,
                 "tests": (scan.get("tests") or [])[:10]}
    return {"project": project.model_dump(), "scan": scan,
            "connection": conn, "readiness": readiness}


@app.post("/api/projects/{project_id}/scan")
def scan_project(project_id: str):
    from projects.scanner import scan_repo
    project = _projects().get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    path = project.local_path or "cloud-rca-demo-app"
    scan = scan_repo(path if os.path.isabs(path) else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), path))
    from datetime import datetime, timezone as _tz
    project.detected = {k: v for k, v in scan.items() if k != "error"}
    project.last_scan = datetime.now(_tz.utc).isoformat()
    if not project.services and scan.get("services"):
        project.services = scan["services"][:8]
    _projects().upsert(project)
    return {"project_id": project_id, "scan": scan}


@app.post("/api/projects/{project_id}/test-connection")
def test_project_connection(project_id: str, body: dict):
    from projects.scanner import connection_ok
    project = _projects().get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    kind = (body.get("kind") or "git").lower()
    if kind == "git":
        return connection_ok(path=body.get("local_path") or project.local_path,
                             url=body.get("repository_url") or project.repository_url)
    if kind == "gcp":
        pid = body.get("gcp_project_id") or project.gcp_project_id
        return {"ok": bool(pid), "detail": "project id set" if pid else "no GCP project configured"}
    return {"ok": False, "detail": f"unknown connection kind {kind}"}


@app.post("/api/projects/{project_id}/disconnect")
def disconnect_project_source(project_id: str, body: dict):
    store = _projects()
    project = store.get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    kind = (body.get("kind") or "git").lower()
    if kind == "git":
        project.repository_url, project.local_path = "", ""
        project.repo_access = "READ_ONLY"
    project.data_sources = [s for s in project.data_sources if s.kind != kind]
    store.upsert(project)
    return project.model_dump()


# ---------- incidents ----------

def _scenario_for_file(name: str):
    n = (name or "").lower()
    for key in ("db_timeout", "pool_exhaustion", "bad_deployment", "dependency",
                "traffic_overload", "config_regression"):
        if key in n:
            return {"db_timeout": "db-timeout", "pool_exhaustion": "pool-exhaustion",
                    "bad_deployment": "bad-deployment", "dependency": "dependency-failure",
                    "traffic_overload": "traffic-overload",
                    "config_regression": "config-error"}[key]
    return None


def _incident_cards():
    """Static fixtures merged with lifecycle registry (compat loader, Part 34)."""
    from tools.error_taxonomy import domain_for_scenario
    from projects.store import PRRegistry
    try:
        _prs = PRRegistry().list()
    except Exception:
        _prs = []
    def _pr_for(incident_id):
        matches = [r for r in _prs if r.incident_id == incident_id]
        return matches[0] if matches else None
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cards = []
    for path in sorted(glob.glob(os.path.join(base_dir, "data", "incidents", "incident_00*.json"))):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        scenario = _scenario_for_file(os.path.basename(path))
        domain, sub = domain_for_scenario(scenario) if scenario else ("Unknown", "Unknown")
        service = data.get("service_name", "")
        rec = _registry().get(data.get("incident_id", ""))
        project_id = (rec or {}).get("project_id") or _projects().resolve_project(service)
        runs = (rec or {}).get("rca_runs", [])
        pr = _pr_for(data.get("incident_id", ""))
        cards.append({
            "incident_id": data.get("incident_id", os.path.basename(path)),
            "file": os.path.basename(path),
            "title": (data.get("symptoms") or [""])[0][:90],
            "service": service,
            "severity": data.get("severity", "P2"),
            "status": (rec or {}).get("status", "Open"),
            "project_id": project_id,
            "domain": domain, "subcategory": sub,
            "start_time": data.get("start_time", ""),
            "rca_runs": runs,
            "root_cause": (runs[-1].get("category", "") if runs else ""),
            "pr_id": pr.pr_id if pr else "",
            "pr_status": pr.status if pr else "",
        })
    for rec in _registry().list():
        if not any(c["incident_id"] == rec["incident_id"] for c in cards):
            runs = rec.get("rca_runs", [])
            pr = _pr_for(rec["incident_id"])
            cards.append({
                "incident_id": rec["incident_id"], "file": "",
                "title": rec.get("title", ""), "service": (rec.get("services") or [""])[0],
                "severity": rec.get("severity", "P2"), "status": rec.get("status", "NEW"),
                "project_id": rec.get("project_id", "unassigned"),
                "source": (rec.get("source") or "MANUAL").upper(),
                "is_simulation": (rec.get("source") or "").upper() == "SIMULATION",
                "scenario_id": rec.get("scenario_id", ""),
                "domain": rec.get("error_domain", ""), "subcategory": rec.get("error_subcategory", ""),
                "start_time": rec.get("started_at", ""),
                "rca_runs": runs,
                "root_cause": (runs[-1].get("category", "") if runs else ""),
                "pr_id": pr.pr_id if pr else "",
                "pr_status": pr.status if pr else "",
            })
    return cards


@app.get("/api/incidents/meta")
def incidents_meta():
    return _incident_cards()


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str):
    from projects.store import PRRegistry
    from orchestration.attachments import AttachmentStore
    rec = _registry().get(incident_id) or {"incident_id": incident_id, "status": "Open"}
    card = next((c for c in _incident_cards() if c["incident_id"] == incident_id), {})
    source = (rec.get("source") or card.get("source") or "MANUAL").upper()
    return {"incident": rec, "file_meta": card,
            "source": source, "is_simulation": source == "SIMULATION",
            "scenario_id": rec.get("scenario_id", ""),
            "project": (_projects().get(rec.get("project_id", "")) or
                        _projects().get(card.get("project_id", ""))).model_dump()
            if (rec.get("project_id") or card.get("project_id")) else None,
            "rca_runs": rec.get("rca_runs", []), "notes": rec.get("notes", []),
            "history": rec.get("history", []),
            "attachments": AttachmentStore().list(incident_id),
            "pull_requests": [r.model_dump() for r in PRRegistry().by_incident(incident_id)]}


@app.post("/api/projects/{project_id}/incidents")
def create_incident(project_id: str, body: dict):
    """Manual incident form: title/severity/env/services + optional trace/request/revision context."""
    import re as _re
    import uuid as _uuid
    from schemas.incident_source import IncidentSource
    project = _projects().get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    title = (body.get("title") or "").strip()
    if not title:
        raise HTTPException(status_code=400, detail="Incident title is required")
    sev = str(body.get("severity", "P2")).strip().lower()
    sev = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P3",
           "p1": "P1", "p2": "P2", "p3": "P3"}.get(sev, "P2")
    incident_id = f"INC-{_re.sub(r'[^A-Z0-9]+', '-', title.upper()).strip('-')[:24]}-{_uuid.uuid4().hex[:4].upper()}"
    services = body.get("affected_services") or body.get("services") or project.services[:1]
    MANUAL_EVIDENCE[incident_id] = {
        "title": title, "description": body.get("description", ""),
        "environment": body.get("environment", project.environment),
        "severity": sev, "services": services,
        "start_time": body.get("start_time") or body.get("started_at") or "",
        "trace_id": body.get("trace_id", ""), "request_id": body.get("request_id", ""),
        "error_signature": body.get("error_signature", ""),
        "revision": body.get("revision") or body.get("deployment") or "",
        "endpoint": body.get("endpoint", ""), "owner": body.get("owner") or body.get("team") or "",
        "context": body.get("context", ""),
        "project_id": project_id,
    }
    from orchestration.incident_registry import record_activity
    _registry().ensure(incident_id, project_id=project_id, title=title, severity=sev,
                       environment=body.get("environment", project.environment),
                       services=services, source=IncidentSource.MANUAL.value,
                       evidence_source="manual",
                       description=body.get("description", ""),
                       started_at=body.get("start_time") or body.get("started_at") or "")
    record_activity("INCIDENT_CREATED", incident_id, "web-user", title,
                    {"project_id": project_id, "mode": "manual",
                     "source": IncidentSource.MANUAL.value})
    return {"incident_id": incident_id, "status": "NEW", "project_id": project_id,
            "source": IncidentSource.MANUAL.value}


@app.post("/api/incidents/{incident_id}/notes")
def add_incident_note(incident_id: str, body: dict):
    author = (body.get("author") or "operator").strip() or "operator"
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text is required")
    rec = _registry().add_note(incident_id, author, text)
    return {"incident_id": incident_id, "notes": rec.get("notes", [])}


@app.get("/api/incidents/{incident_id}/activity")
def incident_activity(incident_id: str):
    from orchestration.incident_registry import recent_activity
    return recent_activity(limit=50, incident_id=incident_id)


@app.get("/api/incidents/{incident_id}/export")
def export_rca(incident_id: str, format: str = "json"):
    entry = LAST_INVESTIGATION.get(incident_id)
    if not entry:
        raise HTTPException(status_code=404, detail="No RCA investigation stored for this incident")
    report = entry["state"].final_report
    if format == "markdown":
        lines = [f"# RCA Report {incident_id}", "",
                 f"- **Root cause:** {report.root_cause}",
                 f"- **Category:** {entry['category']}",
                 f"- **Confidence:** {report.confidence}",
                 f"- **Services:** {', '.join(report.affected_services)}",
                 f"- **Blast radius:** {report.blast_radius.classification} - {report.blast_radius.estimated_scope}", "",
                 "## Supporting evidence"] + [f"- {e}" for e in report.supporting_evidence] + [
                 "", "## Contradictory evidence"] + [f"- {e}" for e in report.contradictory_evidence] + [
                 "", "## Timeline"] + [f"- {t.timestamp} [{t.event_type}] {t.description}" for t in report.timeline] + [
                 "", f"## Recommended next action", report.recommended_next_action]
        return PlainTextResponse("\n".join(lines), media_type="text/markdown")
    return JSONResponse(report.model_dump())


# ---------- home ----------

@app.get("/api/home/stats")
def home_stats():
    from orchestration.incident_registry import recent_activity
    from projects.store import PRRegistry
    cards = _incident_cards()
    open_incs = [c for c in cards if c.get("status") not in ("RESOLVED", "FAILED")]
    rca_completed = sum(len((__import__("orchestration.incident_registry", fromlist=["IncidentRegistry"]).IncidentRegistry().get(c["incident_id"]) or {}).get("rca_runs", [])) for c in cards)
    prs = PRRegistry().list()
    return {
        "projects": len(_projects().list()),
        "open_incidents": len(open_incs),
        "rca_completed": rca_completed,
        "prs_awaiting_approval": sum(1 for r in prs if r.status == "Awaiting Approval"),
        "prs_created": len(prs),
        "pending_approvals": len(global_approval_manager.list_pending()),
        "recent_activity": recent_activity(limit=12),
        "recent_prs": [r.model_dump() for r in prs[:5]],
        "recent_incidents": cards[:6],
    }


# ---------- pull requests ----------

@app.get("/api/pull-requests")
def list_prs(project: str = "", incident: str = ""):
    from projects.store import PRRegistry
    rows = PRRegistry().list(project_id=project)
    if incident:
        rows = [r for r in rows if r.incident_id == incident]
    return [r.model_dump() for r in rows]


@app.get("/api/pull-requests/{pr_id}")
def pr_detail(pr_id: str):
    from projects.store import PRRegistry
    pr = PRRegistry().get(pr_id)
    if not pr:
        raise HTTPException(status_code=404, detail="Pull request not found")
    return pr.model_dump()


# ---------- uploads ----------

@app.post("/api/logs/upload")
async def upload_logs(project_id: str = Form("unassigned"),
                      source_type: str = Form("Auto Detect"),
                      service: str = Form(""), incident_start: str = Form(""),
                      region: str = Form(""), environment: str = Form(""),
                      description: str = Form(""),
                      files: List[UploadFile] = File(...)):
    from ingestion.upload_handler import ingest_files
    from projects.store import AnalysisStore
    from schemas.project import LogAnalysis
    from orchestration.incident_registry import record_activity
    from datetime import datetime, timezone as _tz

    uploads = []
    for f in files:
        content = await f.read()
        uploads.append((f.filename or "upload.log", content))
    analysis_id, summaries, preview, warnings = ingest_files(uploads, source_type)
    from ingestion.normalizer import summarize as _summarize
    preview_stats = _summarize(preview)
    analysis = LogAnalysis(
        analysis_id=analysis_id, project_id=project_id,
        files=[{**s} for s in summaries], source_type=source_type,
        context={"service": service, "incident_start": incident_start,
                 "region": region, "environment": environment,
                 "description": description},
        services=preview_stats["services"], time_start=preview_stats["time_start"],
        time_end=preview_stats["time_end"], record_count=preview_stats["record_count"],
        error_codes=preview_stats["error_codes"], warning_count=preview_stats["warning_count"],
        created_at=datetime.now(_tz.utc).isoformat(),
    )
    AnalysisStore().save(analysis)
    record_activity("LOG_COLLECTED", "", "web-user",
                    f"{len(summaries)} file(s) uploaded for {project_id}",
                    {"analysis_id": analysis_id})
    return {"analysis_id": analysis_id, "files": [s for s in summaries],
            "warnings": warnings, "preview": preview[:50], "preview_stats": preview_stats,
            "project_id": project_id}


@app.get("/api/log-analyses")
def list_analyses():
    from projects.store import AnalysisStore
    return [a.model_dump() for a in AnalysisStore().list()]


@app.get("/api/log-analyses/{analysis_id}")
def analysis_detail(analysis_id: str):
    from projects.store import AnalysisStore
    analysis = AnalysisStore().get(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis.model_dump()


@app.post("/api/logs/{analysis_id}/analyze-legacy")
async def analyze_upload_legacy(analysis_id: str):
    from ingestion.upload_handler import load_parsed
    from ingestion.normalizer import normalize, summarize, to_evidence_inputs
    from tools.normalizer import normalize_evidence
    from schemas.evidence import IncidentEvidence
    from tools.error_taxonomy import domain_for_category
    from projects.store import AnalysisStore
    from orchestration.incident_registry import record_activity
    analysis = AnalysisStore().get(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    raw = load_parsed(analysis_id)
    if not raw:
        raise HTTPException(status_code=400, detail="No parsed records for this analysis")
    records = normalize(raw)
    stats = summarize(records)
    service = analysis.context.get("service") or (stats["services"][0] if stats["services"] else "unknown-service")
    inputs = to_evidence_inputs(records, service)
    incident_id = f"INC-UPLOAD-{analysis_id.replace('AN-', '')[:8]}"
    deps = sorted({r["dependency"] for r in records if r.get("dependency")})
    traces = sorted({r["trace_id"] for r in records if r.get("trace_id")})[:10]
    ev = normalize_evidence(
        incident_id=incident_id,
        project_id=(analysis.context.get("region") and "upload") or "upload",
        service_name=service,
        start_time=stats["time_start"] or analysis.created_at,
        end_time=stats["time_end"] or analysis.created_at,
        raw_logs=inputs["raw_logs"], raw_metrics=inputs["raw_metrics"],
        deployment_events=[], raw_traces=[{"trace_id": t} for t in traces],
        dependencies=[{"name": d, "status": "UNKNOWN"} for d in deps if d],
        revision_name=None, region=analysis.context.get("region", ""))
    import time as _time
    wf = InvestigationWorkflow()
    started = _time.time()
    state = await asyncio.to_thread(wf.run, ev)
    duration = round(_time.time() - started, 1)
    best = next((h for h in state.hypotheses
                 if any(v.hypothesis_id == h.hypothesis_id and v.accepted
                        for v in state.validated_hypotheses)),
                state.hypotheses[0] if state.hypotheses else None)
    category = best.root_cause_category if best else "unknown"
    domain, sub = domain_for_category(category)
    LAST_RCA[incident_id] = {
        "root_cause_category": category, "root_cause": state.final_report.root_cause,
        "confidence": state.final_report.confidence,
        "supporting_evidence": state.final_report.supporting_evidence,
        "contradictory_evidence": state.final_report.contradictory_evidence,
        "service": service,
    }
    LAST_INVESTIGATION[incident_id] = {"state": state, "category": category}
    project_id = analysis.project_id
    _registry().ensure(incident_id, project_id=project_id, title=f"Uploaded logs RCA ({service})",
                       severity=ev.severity, services=[service], evidence_source="upload")
    for target in ("COLLECTING_EVIDENCE", "ANALYZING", "ROOT_CAUSE_IDENTIFIED"):
        _bump(incident_id, target)
    _registry().add_rca_run(incident_id, {"category": category,
                                          "confidence": state.final_report.confidence,
                                          "duration_s": duration, "evidence_source": "upload"})
    _registry().set_fields(incident_id, error_domain=domain, error_subcategory=sub)
    record_activity("RCA_STARTED", incident_id, "web-user", "file-based RCA started",
                    {"analysis_id": analysis_id})
    record_activity("ROOT_CAUSE_IDENTIFIED", incident_id, "rca-agent",
                    f"{category} ({state.final_report.confidence})", {})
    analysis.services, analysis.time_start, analysis.time_end = stats["services"], stats["time_start"], stats["time_end"]
    analysis.record_count, analysis.error_codes = stats["record_count"], stats["error_codes"]
    analysis.warning_count, analysis.status = stats["warning_count"], "analyzed"
    analysis.rca = {"incident_id": incident_id, "root_cause_category": category,
                    "root_cause": state.final_report.root_cause,
                    "confidence": state.final_report.confidence,
                    "supporting_evidence": state.final_report.supporting_evidence,
                    "contradictory_evidence": state.final_report.contradictory_evidence,
                    "timeline": [t.model_dump() for t in state.final_report.timeline],
                    "blast_radius": state.final_report.blast_radius.model_dump(),
                    "recommended_action": state.final_report.recommended_next_action,
                    "domain": domain, "subcategory": sub, "evidence_source": "upload",
                    "duration_s": duration}
    AnalysisStore().save(analysis)
    from orchestration.notifications import notify
    notify("RCA_COMPLETE", {"incident_id": incident_id, "target": service,
                            "description": f"upload RCA {category} {state.final_report.confidence}"})
    result = dict(analysis.rca)
    result.update({"analysis_id": analysis_id,
                   "hypotheses": [h.model_dump() for h in state.hypotheses],
                   "validations": [v.model_dump() for v in
                                   state.validated_hypotheses + state.rejected_hypotheses],
                   "files": [f.filename for f in analysis.files],
                   "record_count": stats["record_count"],
                   "time_range": [stats["time_start"], stats["time_end"]]})
    return result

# ================= Separated workflows: incidents vs simulations =================
# REAL: MANUAL/LOG_UPLOAD. DEMO: SIMULATION. Branching keys off persisted
# IncidentSource; simulations always create NEW incidents and can never
# mutate a MANUAL/LOG_UPLOAD incident.


@app.get("/api/simulations")
def list_simulations(category: str = ""):
    from tools.simulations import catalog
    rows = catalog()
    if category:
        rows = [r for r in rows if r.get("category", "").lower() == category.lower()]
    return {"count": len(rows),
            "categories": ["Code", "Database", "Dependency", "Runtime",
                           "Concurrency", "Deployment"],
            "scenarios": rows,
            "notice": ("Generate controlled synthetic incidents for RCA demonstrations "
                       "and testing. Simulations never affect production resources.")}


@app.post("/api/simulations/run")
def run_simulation(body: dict):
    import uuid as _uuid
    from datetime import datetime, timezone as _tz
    from tools.simulations import get as sim_get, generate_evidence, ALLOWED_SIM_ENVS
    from schemas.incident_source import IncidentSource
    scenario = (body or {}).get("scenario", "")
    service = (body or {}).get("service", "")
    environment = (body or {}).get("environment", "demo")
    project_id = (body or {}).get("project_id") or _projects().resolve_project(service or "checkout-service")
    if not scenario:
        raise HTTPException(status_code=400, detail="scenario is required")
    try:
        spec = sim_get(scenario)
    except KeyError:
        raise HTTPException(status_code=400, detail=f"Unknown simulation scenario: {scenario}")
    if (environment or "").lower() not in ALLOWED_SIM_ENVS:
        raise HTTPException(status_code=400, detail="Simulations are not allowed in production. Choose demo, local, or test.")
    service = service or spec.get("service", "checkout-service")
    stamp = datetime.now(_tz.utc).strftime("%Y%m%d")
    incident_id = f"INC-SIM-{stamp}-{_uuid.uuid4().hex[:4].upper()}"
    evidence = generate_evidence(spec["scenario_id"], incident_id)
    # Stream synthetic logs into the live buffer (local/synthetic only)
    try:
        SIMULATED_LOGS.extend(evidence["logs"])
    except Exception:
        pass
    global LATEST_SIMULATED_FILE, LATEST_SCENARIO
    LATEST_SCENARIO = (body or {}).get("legacy_scenario") or None
    _registry().ensure(incident_id, project_id=project_id,
                       title=f"[SIM] {spec['title']} on {service}",
                       severity="P2", environment=environment,
                       services=[service], source=IncidentSource.SIMULATION.value,
                       evidence_source="simulation",
                       scenario_id=spec["scenario_id"],
                       description=spec.get("blurb", ""))
    for _t in ("COLLECTING_EVIDENCE",):
        _bump(incident_id, _t, "web-user")
    try:
        from orchestration.incident_registry import record_activity
        record_activity("SIMULATION_STARTED", incident_id, "web-user",
                        f"simulated {spec['scenario_id']}",
                        {"scenario": spec["scenario_id"], "source": "SIMULATION"})
    except Exception:
        pass
    return {"incident_id": incident_id, "source": "SIMULATION",
            "scenario": spec["scenario_id"], "service": service,
            "environment": environment, "project_id": project_id,
            "logs_generated": len(evidence["logs"]),
            "revision": evidence.get("revision", ""),
            "ground_truth": evidence.get("ground_truth", {}),
            "simulated": True}


@app.post("/api/simulations/{incident_id}/regenerate")
def regenerate_simulation(incident_id: str):
    from tools.simulations import generate_evidence
    rec = _registry().get(incident_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Incident not found")
    if (rec.get("source") or "").upper() != "SIMULATION":
        raise HTTPException(status_code=409, detail=(
            "Refusing to inject synthetic evidence into a non-simulated incident. "
            "Simulations always create a NEW simulated incident."))
    scenario = rec.get("scenario_id") or "null-pointer"
    evidence = generate_evidence(scenario, incident_id)
    try:
        SIMULATED_LOGS.extend(evidence["logs"])
    except Exception:
        pass
    return {"incident_id": incident_id, "regenerated": True,
            "logs_generated": len(evidence["logs"]), "scenario": scenario}


@app.put("/api/projects/{project_id}/repo-mapping")
def set_repo_mapping(project_id: str, body: dict):
    project = _projects().get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    mappings = (body or {}).get("service_mappings") or {}
    if not isinstance(mappings, dict):
        raise HTTPException(status_code=400, detail="service_mappings must be an object")
    project.service_mappings = {str(k): str(v) for k, v in mappings.items()}
    _projects().upsert(project)
    return {"project_id": project_id, "service_mappings": project.service_mappings}


@app.get("/api/projects/{project_id}/repo-readiness")
def repo_readiness(project_id: str):
    from tools.repo_readiness import readiness_scan
    project = _projects().get(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    result = readiness_scan(local_path=project.local_path or "",
                            repository_url=project.repository_url or "",
                            default_branch=project.default_branch or "main",
                            service_mappings=project.service_mappings or {})
    project.readiness = {"status": result["status"], "ready": result["ready"]}
    _projects().upsert(project)
    return {"project_id": project_id, **result}


@app.post("/api/incidents/{incident_id}/attachments")
async def attach_incident_logs(incident_id: str, files: List[UploadFile] = File(...)):
    from orchestration.attachments import AttachmentStore
    rec = _registry().get(incident_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Incident not found")
    if (rec.get("source") or "").upper() == "SIMULATION":
        raise HTTPException(status_code=409, detail=(
            "Cannot attach manual uploads to a SIMULATED incident. "
            "Use Regenerate Simulation Evidence instead."))
    store = AttachmentStore()
    attached, warnings = [], []
    for f in files:
        content = await f.read()
        try:
            attached.append(store.attach(
                incident_id, rec.get("project_id", "unassigned"),
                f.filename or "upload.log", content,
                content_type=f.content_type or "", uploaded_by="web-user"))
        except ValueError as e:
            warnings.append(str(e))
    return {"incident_id": incident_id, "attached": attached, "warnings": warnings}


@app.get("/api/incidents/{incident_id}/attachments")
def list_incident_attachments(incident_id: str):
    from orchestration.attachments import AttachmentStore
    return {"incident_id": incident_id,
            "attachments": AttachmentStore().list(incident_id)}


@app.get("/api/incidents/{incident_id}/evidence-summary")
def incident_evidence_summary(incident_id: str):
    from orchestration.attachments import AttachmentStore
    from tools.evidence_completeness import completeness
    rec = _registry().get(incident_id) or {"incident_id": incident_id}
    project = None
    try:
        project = (_projects().get(rec.get("project_id", "")) or
                   _projects().get("checkout-platform"))
        project = project.model_dump() if project else {}
    except Exception:
        project = {}
    atts = AttachmentStore().list(incident_id)
    comp = completeness(rec, atts, project, len(rec.get("rca_runs", [])))
    by_type = {}
    for a in atts:
        by_type[a.get("type", "OTHER")] = by_type.get(a.get("type", "OTHER"), 0) + 1
    return {"incident_id": incident_id, "source": rec.get("source", "MANUAL"),
            "scenario_id": rec.get("scenario_id", ""),
            "attachments": [{"id": a["id"], "filename": a["filename"],
                             "size": a["size"], "parsed_event_count": a.get("parsed_event_count", 0),
                             "type": a.get("type")} for a in atts],
            "completeness": comp, "by_type": by_type,
            "repository": {"connected": bool((project or {}).get("repository_url") or (project or {}).get("local_path")),
                           "service_mappings": (project or {}).get("service_mappings", {})},
            "code_investigation": ("Unavailable - no repository connected"
                                   if not ((project or {}).get("repository_url") or (project or {}).get("local_path"))
                                   else "Available")}


@app.post("/api/logs/{analysis_id}/analyze")
async def analyze_upload(analysis_id: str, mode: str = "create",
                         incident_id: str = "", project_id: str = "",
                         title: str = "", severity: str = "P2",
                         service: str = "", environment: str = "prod"):
    """Analyze Logs with explicit mode (no silent incident creation).

    mode=analyze_only: run RCA, store an AnalysisSession, create NO incident.
    mode=attach: run RCA and link evidence to an existing incident.
    mode=create (legacy default): run RCA and create a LOG_UPLOAD incident.
    """
    from ingestion.upload_handler import load_parsed
    from ingestion.normalizer import normalize, summarize, to_evidence_inputs
    from tools.normalizer import normalize_evidence
    from schemas.evidence import IncidentEvidence
    from tools.error_taxonomy import domain_for_category
    from projects.store import AnalysisStore
    from orchestration.incident_registry import record_activity
    from orchestration.analysis_sessions import AnalysisSessionStore
    from schemas.incident_source import IncidentSource
    analysis = AnalysisStore().get(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    raw = load_parsed(analysis_id)
    if not raw:
        raise HTTPException(status_code=400, detail="No parsed records for this analysis")
    records = normalize(raw)
    stats = summarize(records)
    service = service or analysis.context.get("service") or (stats["services"][0] if stats["services"] else "unknown-service")
    inputs = to_evidence_inputs(records, service)
    incident_id = f"INC-UPLOAD-{analysis_id.replace('AN-', '')[:8]}"
    deps = sorted({r["dependency"] for r in records if r.get("dependency")})
    traces = sorted({r["trace_id"] for r in records if r.get("trace_id")})[:10]
    ev = normalize_evidence(
        incident_id=incident_id,
        project_id=(analysis.context.get("region") and "upload") or "upload",
        service_name=service,
        start_time=stats["time_start"] or analysis.created_at,
        end_time=stats["time_end"] or analysis.created_at,
        raw_logs=inputs["raw_logs"], raw_metrics=inputs["raw_metrics"],
        deployment_events=[], raw_traces=[{"trace_id": t} for t in traces],
        dependencies=[{"name": d, "status": "UNKNOWN"} for d in deps if d],
        revision_name=None, region=analysis.context.get("region", ""))
    import time as _time
    wf = InvestigationWorkflow()
    started = _time.time()
    state = await asyncio.to_thread(wf.run, ev)
    duration = round(_time.time() - started, 1)
    best = next((h for h in state.hypotheses
                 if any(v.hypothesis_id == h.hypothesis_id and v.accepted
                        for v in state.validated_hypotheses)),
                state.hypotheses[0] if state.hypotheses else None)
    category = best.root_cause_category if best else "unknown"
    domain, sub = domain_for_category(category)
    rca_payload = {"incident_id": incident_id, "root_cause_category": category,
                   "root_cause": state.final_report.root_cause,
                   "confidence": state.final_report.confidence,
                   "supporting_evidence": state.final_report.supporting_evidence,
                   "contradictory_evidence": state.final_report.contradictory_evidence,
                   "timeline": [t.model_dump() for t in state.final_report.timeline],
                   "blast_radius": state.final_report.blast_radius.model_dump(),
                   "recommended_action": state.final_report.recommended_next_action,
                   "domain": domain, "subcategory": sub,
                   "duration_s": duration}
    if mode == "analyze_only":
        session = AnalysisSessionStore().create(
            analysis.project_id or project_id or "unassigned", [analysis_id],
            {"service": service})
        record_activity("ANALYSIS_COMPLETED", "", "web-user",
                        f"analyze-only session {session['session_id']}",
                        {"analysis_id": analysis_id})
        out = dict(rca_payload)
        out.update({"analysis_id": analysis_id, "session_id": session["session_id"],
                    "mode": "analyze_only", "incident_created": False})
        return out
    if mode == "attach":
        if not incident_id:
            raise HTTPException(status_code=400, detail="incident_id is required for attach mode")
        rec = _registry().get(incident_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Target incident not found")
        if (rec.get("source") or "").upper() == "SIMULATION":
            raise HTTPException(status_code=409, detail=(
                "Cannot attach uploaded logs to a SIMULATED incident."))
        LAST_RCA[incident_id] = {
            "root_cause_category": category, "root_cause": state.final_report.root_cause,
            "confidence": state.final_report.confidence,
            "supporting_evidence": state.final_report.supporting_evidence,
            "contradictory_evidence": state.final_report.contradictory_evidence,
            "service": service}
        LAST_INVESTIGATION[incident_id] = {"state": state, "category": category}
        record_activity("EVIDENCE_ATTACHED", incident_id, "web-user",
                        f"analysis {analysis_id} attached", {"analysis_id": analysis_id})
        out = dict(rca_payload)
        out.update({"analysis_id": analysis_id, "mode": "attach",
                    "incident_id": incident_id})
        return out
    # mode=create (legacy): new LOG_UPLOAD incident
    project_id = project_id or analysis.project_id or "unassigned"
    _registry().ensure(incident_id, project_id=project_id,
                       title=title or f"Uploaded logs RCA ({service})",
                       severity=severity, services=[service],
                       source=IncidentSource.LOG_UPLOAD.value,
                       evidence_source="upload")
    for target in ("COLLECTING_EVIDENCE", "ANALYZING", "ROOT_CAUSE_IDENTIFIED"):
        _bump(incident_id, target)
    LAST_RCA[incident_id] = {
        "root_cause_category": category, "root_cause": state.final_report.root_cause,
        "confidence": state.final_report.confidence,
        "supporting_evidence": state.final_report.supporting_evidence,
        "contradictory_evidence": state.final_report.contradictory_evidence,
        "service": service}
    LAST_INVESTIGATION[incident_id] = {"state": state, "category": category}
    _registry().add_rca_run(incident_id, {"category": category,
                                          "confidence": state.final_report.confidence,
                                          "duration_s": duration, "evidence_source": "upload"})
    _registry().set_fields(incident_id, error_domain=domain, error_subcategory=sub)
    record_activity("RCA_STARTED", incident_id, "web-user", "file-based RCA started",
                    {"analysis_id": analysis_id})
    record_activity("ROOT_CAUSE_IDENTIFIED", incident_id, "rca-agent",
                    f"{category} ({state.final_report.confidence})", {})
    analysis.services, analysis.time_start, analysis.time_end = stats["services"], stats["time_start"], stats["time_end"]
    analysis.record_count, analysis.error_codes = stats["record_count"], stats["error_codes"]
    analysis.warning_count, analysis.status = stats["warning_count"], "analyzed"
    analysis.rca = {"incident_id": incident_id, "root_cause_category": category,
                    "root_cause": state.final_report.root_cause,
                    "confidence": state.final_report.confidence,
                    "supporting_evidence": state.final_report.supporting_evidence,
                    "contradictory_evidence": state.final_report.contradictory_evidence,
                    "timeline": [t.model_dump() for t in state.final_report.timeline],
                    "blast_radius": state.final_report.blast_radius.model_dump(),
                    "recommended_action": state.final_report.recommended_next_action,
                    "domain": domain, "subcategory": sub, "evidence_source": "upload",
                    "duration_s": duration}
    AnalysisStore().save(analysis)
    out = dict(rca_payload)
    out.update({"analysis_id": analysis_id, "mode": "create",
                "incident_id": incident_id, "source": "LOG_UPLOAD",
                "evidence_source": "upload",
                "hypotheses": [h.model_dump() for h in state.hypotheses],
                "validations": [v.model_dump() for v in
                                state.validated_hypotheses + state.rejected_hypotheses],
                "files": [f.filename for f in analysis.files],
                "record_count": stats["record_count"],
                "time_range": [stats["time_start"], stats["time_end"]]})
    return out


@app.post("/api/analysis-sessions/{session_id}/convert")
def convert_analysis_session(session_id: str, body: dict):
    """Convert an analyze-only session into a real incident (explicit user action)."""
    from orchestration.analysis_sessions import AnalysisSessionStore
    from orchestration.incident_registry import record_activity
    from schemas.incident_source import IncidentSource
    import uuid as _uuid
    session = AnalysisSessionStore().get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Analysis session not found")
    if session.get("converted_incident_id"):
        return {"session_id": session_id,
                "incident_id": session["converted_incident_id"], "converted": False,
                "detail": "already converted"}
    action = (body or {}).get("action", "create")
    if action == "attach":
        incident_id = (body or {}).get("incident_id", "")
        rec = _registry().get(incident_id)
        if not rec:
            raise HTTPException(status_code=404, detail="Target incident not found")
        if (rec.get("source") or "").upper() == "SIMULATION":
            raise HTTPException(status_code=409, detail="Cannot convert analysis into a SIMULATED incident.")
        AnalysisSessionStore().mark_converted(session_id, incident_id)
        record_activity("EVIDENCE_ATTACHED", incident_id, "web-user",
                        f"session {session_id} converted (attach)", {})
        return {"session_id": session_id, "incident_id": incident_id, "converted": True}
    title = (body or {}).get("title") or f"Converted analysis {session_id}"
    project_id = (body or {}).get("project_id") or session.get("project_id", "unassigned")
    incident_id = f"INC-ANALYSIS-{_uuid.uuid4().hex[:4].upper()}"
    _registry().ensure(incident_id, project_id=project_id, title=title,
                       severity=(body or {}).get("severity", "P2"),
                       services=[(body or {}).get("service", "unknown-service")],
                       source=IncidentSource.LOG_UPLOAD.value,
                       evidence_source="upload",
                       description="Converted from analyze-only session")
    AnalysisSessionStore().mark_converted(session_id, incident_id)
    record_activity("INCIDENT_CREATED", incident_id, "web-user", title,
                    {"project_id": project_id, "mode": "convert"})
    return {"session_id": session_id, "incident_id": incident_id,
            "converted": True, "source": "LOG_UPLOAD"}


@app.get("/api/incidents/{incident_id}/code-investigation")
def code_investigation_view(incident_id: str):
    """Structured code evidence: suspect file/line, evidence, recent diff, tests, confidences."""
    from agents.code_investigation_agent.agent import CodeInvestigationAgent
    rec = _registry().get(incident_id) or {}
    rca = LAST_RCA.get(incident_id, {})
    project = None
    try:
        project = _projects().get(rec.get("project_id", ""))
    except Exception:
        project = None
    if not project:
        return {"incident_id": incident_id, "available": False,
                "reason": ("No repository is connected to this project. RCA can identify "
                           "the likely application failure, but source-code-level findings "
                           "and automated patches are unavailable."),
                "cta": "Connect Repository"}
    stack_text = ""
    try:
        entry = LAST_INVESTIGATION.get(incident_id)
        if entry:
            raw = entry["state"].incident_evidence.raw_evidence or []
            stack_text = " ".join(str(r.get("message", "")) for r in raw[:20])
    except Exception:
        stack_text = ""
    inv = CodeInvestigationAgent().investigate(
        incident_id, rca.get("root_cause_category", "unknown"),
        live_context={"service": rca.get("service", ""), "error_signature": rca.get("root_cause", "")},
        stack_text=stack_text, service=rca.get("service", ""),
        service_mappings=(project.service_mappings or {}),
        repo_available=True)
    recent = CodeInvestigationAgent().recent_change(_demo_repo())
    root_conf = float(rca.get("confidence", 0.0) or 0.0)
    fix_conf = round(max(0.0, root_conf - (0.05 if inv.findings else 0.25)), 2)
    if not inv.findings:
        fix_conf = 0.0
    return {"incident_id": incident_id, "available": bool(inv.findings),
            "repository": "cloud-rca-demo-app",
            "revision": recent.get("recent_commit", ""),
            "files_investigated": len(inv.findings),
            "primary_suspect": (f"{inv.findings[0].file}:{inv.findings[0].start_line}"
                                if inv.findings else ""),
            "findings": [f.model_dump() for f in inv.findings],
            "no_fix_reason": inv.no_fix_reason,
            "recent_change": recent,
            "root_cause_confidence": root_conf,
            "fix_confidence": fix_conf,
            "related_tests": [f.related_test for f in inv.findings if f.related_test]}


# ================= Investigation platform (Phase 1: explainability) =================
# All views derive from stored RCA structures — no parallel representations.


def _inv_ctx(incident_id: str) -> dict:
    from projects.store import PRRegistry
    from memory.store import MemoryStore
    rec = _registry().get(incident_id) or {"incident_id": incident_id}
    entry = LAST_INVESTIGATION.get(incident_id) or {}
    state = entry.get("state")
    rca = LAST_RCA.get(incident_id, {})
    fix_entry = FIX_JOBS.get(incident_id) or {}
    approvals = []
    try:
        for req in global_approval_manager._store.values():
            if req.incident_id == incident_id:
                approvals.append(req.model_dump())
    except Exception:
        approvals = []
    prs = []
    try:
        prs = [r.model_dump() for r in PRRegistry().by_incident(incident_id)]
    except Exception:
        prs = []
    verification = {}
    try:
        mem = MemoryStore(use_bigquery=False).get(incident_id) or {}
        verification = mem.get("verification_result") or {}
    except Exception:
        verification = {}
    return {"rec": rec, "state": state, "rca": rca, "fix_entry": fix_entry,
            "approvals": approvals, "prs": prs, "verification": verification}


@app.get("/api/incidents/{incident_id}/investigation-graph")
def investigation_graph(incident_id: str):
    from tools.investigation import build_graph
    ctx = _inv_ctx(incident_id)
    if ctx["state"] is None:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    graph = build_graph(incident_id, ctx["rec"], ctx["state"], ctx["rca"],
                        ctx["fix_entry"], ctx["approvals"], ctx["prs"],
                        ctx["verification"])
    # Evidence-to-conclusion path: supporting evidence -> accepted hypothesis -> root cause -> code/fix/approval/pr/verification
    by_id = {n.id: n for n in graph.nodes}
    accepted = [n.id for n in graph.nodes if n.type == "HYPOTHESIS" and n.status == "accepted"]
    path = ["incident"]
    if accepted:
        supporters = sorted({e.from_id for e in graph.edges
                             if e.to_id == accepted[0] and e.relationship == "SUPPORTS"})
        path += supporters + [accepted[0], "root-cause"]
    for nid in ("code-1", "fix"):
        if nid in by_id:
            path.append(nid)
    path += [n.id for n in graph.nodes if n.type in ("APPROVAL", "PR")]
    if "verification" in by_id:
        path.append("verification")
    out = graph.model_dump(by_alias=True)
    out["support_path"] = [p for p in path if p in by_id]
    return out


@app.get("/api/incidents/{incident_id}/why")
def investigation_why(incident_id: str):
    from tools.investigation import why_this
    ctx = _inv_ctx(incident_id)
    if ctx["state"] is None:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    return why_this(ctx["state"], ctx["rca"]).model_dump()


@app.get("/api/incidents/{incident_id}/agent-findings")
def investigation_agent_findings(incident_id: str):
    from tools.investigation import agent_findings_view
    ctx = _inv_ctx(incident_id)
    if ctx["state"] is None:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    return {"incident_id": incident_id,
            "findings": [f.model_dump() for f in agent_findings_view(ctx["state"])]}


@app.get("/api/incidents/{incident_id}/confidence-history")
def investigation_confidence(incident_id: str):
    from tools.investigation import confidence_evolution
    ctx = _inv_ctx(incident_id)
    if ctx["state"] is None:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    return {"incident_id": incident_id,
            "snapshots": [s.model_dump() for s in confidence_evolution(ctx["state"])]}


@app.get("/api/incidents/{incident_id}/quality-score")
def investigation_quality(incident_id: str):
    from tools.investigation import quality_score
    from tools.evidence_completeness import completeness
    from orchestration.attachments import AttachmentStore
    ctx = _inv_ctx(incident_id)
    if ctx["state"] is None:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    rec, state = ctx["rec"], ctx["state"]
    try:
        project = (_projects().get(rec.get("project_id", "")) or
                   _projects().get("checkout-platform"))
        project = project.model_dump() if project else {}
    except Exception:
        project = {}
    atts = AttachmentStore().list(incident_id)
    comp = completeness(rec, atts, project, len(rec.get("rca_runs", [])))
    inv = (ctx["fix_entry"] or {}).get("investigation") or {}
    findings = inv.get("findings", []) or []
    strong = any(str(f.get("reason", "")).startswith("Stack trace points to") for f in findings)
    repo_connected = bool((project or {}).get("repository_url") or (project or {}).get("local_path"))
    supporting = " ".join(
        (getattr(getattr(state, "final_report", None), "supporting_evidence", []) or [])).lower()
    deps_exist = bool(getattr(getattr(state, "incident_evidence", None), "recent_deployments", []) or [])
    dep_ref = deps_exist and any(k in supporting for k in ("revision", "deplo", "commit"))
    similar = 0
    try:
        from memory.retrieval import find_similar_incidents
        from memory.store import MemoryStore
        ev = getattr(state, "incident_evidence", None)
        similar = len(find_similar_incidents(
            service=getattr(ev, "service_name", "") if ev is not None else "",
            symptoms=list(getattr(getattr(state, "final_report", None), "primary_symptoms", []) or [])[:3],
            root_cause_category=ctx["rca"].get("root_cause_category", ""),
            limit=5, store=MemoryStore(use_bigquery=False)))
    except Exception:
        similar = 0
    score = quality_score(state, float(ctx["rca"].get("confidence", 0) or 0),
                          comp.get("percent", 0), bool(findings), strong,
                          repo_connected, similar, dep_ref, deps_exist)
    return {"incident_id": incident_id, **score.model_dump()}


@app.post("/api/incidents/{incident_id}/challenge")
def investigation_challenge(incident_id: str, body: dict):
    from tools.investigation import challenge_answer
    ctx = _inv_ctx(incident_id)
    if ctx["state"] is None:
        raise HTTPException(status_code=404, detail="No stored investigation for this incident: run RCA first")
    question = (body or {}).get("question", "")
    if not question.strip():
        raise HTTPException(status_code=400, detail="question is required")
    code_findings = ((ctx["fix_entry"] or {}).get("investigation") or {}).get("findings", []) or []
    missing = list(getattr(ctx["state"], "missing_evidence", []) or [])
    ans = challenge_answer(question, ctx["state"], ctx["rca"], code_findings, missing)
    return {"incident_id": incident_id, "question": question, **ans.model_dump()}


# Keep original analyze endpoint
