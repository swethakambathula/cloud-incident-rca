"""
Interactive Web Dashboard for Cloud Incident RCA Agent.
Serves a modern, dark-mode visual RCA dashboard for Phase 1 & 2 incidents.
"""
import os
import glob
import json
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
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

app = FastAPI(title="Cloud Incident RCA Agent Dashboard - Phase 4")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Cloud Incident Investigation & RCA Agent</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root { --bg-dark:#0b1329; --card-bg:#151e36; --accent-cyan:#06b6d4; --accent-purple:#8b5cf6; --accent-red:#ef4444; --accent-green:#10b981; --accent-yellow:#f59e0b; --text-main:#f8fafc; --text-muted:#94a3b8; --border-color:#223055; }
        *{box-sizing:border-box;margin:0;padding:0} body{font-family:'Inter',sans-serif;background:var(--bg-dark);color:var(--text-main);display:flex;min-height:100vh}
        .sidebar{width:320px;background:#080d1c;border-right:1px solid var(--border-color);padding:24px;display:flex;flex-direction:column;gap:16px;overflow-y:auto}
        .sidebar h2{font-size:1.15rem;color:var(--accent-cyan)}
        .incident-card{background:var(--card-bg);border:1px solid var(--border-color);padding:12px 14px;border-radius:8px;cursor:pointer;transition:.2s}
        .incident-card:hover,.incident-card.active{border-color:var(--accent-cyan);transform:translateY(-2px);box-shadow:0 4px 14px rgba(6,182,212,.2)}
        .incident-card h4{font-size:.88rem;margin-bottom:4px} .incident-card p{font-size:.75rem;color:var(--text-muted)}
        .main-content{flex:1;padding:24px 32px;overflow-y:auto}
        .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:16px;border-bottom:1px solid var(--border-color);flex-wrap:wrap;gap:12px}
        .btn{background:linear-gradient(135deg,var(--accent-cyan),var(--accent-purple));color:#fff;border:none;padding:10px 18px;border-radius:6px;font-weight:600;cursor:pointer}
        .btn:disabled{opacity:.5;cursor:not-allowed} .btn-red{background:linear-gradient(135deg,#ef4444,#dc2626)} .btn-green{background:linear-gradient(135deg,#10b981,#059669)}
        .sim-bar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;padding:14px;background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;align-items:center}
        .sim-bar strong{font-size:.85rem;color:var(--accent-cyan);margin-right:4px}
        .sim-btn{padding:7px 12px;border-radius:6px;border:1px solid var(--border-color);background:#0b1329;color:var(--text-main);font-size:.78rem;font-weight:600;cursor:pointer}
        .sim-btn:hover{border-color:var(--accent-cyan);background:#1e2a4a}
        .log-panel{background:#020617;border:1px solid var(--border-color);border-radius:8px;padding:12px;height:260px;overflow-y:auto;font-family:'JetBrains Mono',monospace;font-size:.78rem;line-height:1.5}
        .log-line{padding:2px 0;border-bottom:1px solid rgba(34,48,85,.3)} .log-error{color:var(--accent-red)} .log-warn{color:var(--accent-yellow)} .log-info{color:var(--text-muted)}
        .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(350px,1fr));gap:20px;margin-bottom:20px}
        .card{background:var(--card-bg);border:1px solid var(--border-color);border-radius:10px;padding:20px;box-shadow:0 8px 20px rgba(0,0,0,.3)}
        .card-title{font-size:1.05rem;font-weight:600;margin-bottom:14px;color:var(--accent-cyan)}
        .badge{display:inline-block;padding:4px 10px;border-radius:20px;font-size:.75rem;font-weight:600;text-transform:uppercase}
        .badge-red{background:rgba(239,68,68,.2);color:var(--accent-red);border:1px solid var(--accent-red)}
        .badge-yellow{background:rgba(245,158,11,.2);color:var(--accent-yellow);border:1px solid var(--accent-yellow)}
        .badge-green{background:rgba(16,185,129,.2);color:var(--accent-green);border:1px solid var(--accent-green)}
        .item-box{background:#0b1329;border-left:4px solid var(--accent-cyan);padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0;font-size:.88rem}
        .evidence-box{background:#0b1329;border:1px solid var(--border-color);padding:10px 14px;border-radius:6px;margin-bottom:8px;font-size:.85rem}
        .status-dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px} .dot-green{background:var(--accent-green);box-shadow:0 0 6px var(--accent-green)} .dot-red{background:var(--accent-red);animation:pulse 1.2s infinite}
        @keyframes pulse{0%{opacity:1}50%{opacity:.4}100%{opacity:1}}
    </style>
</head>
<body>
    <div class="sidebar">
        <h2>🔍 Cloud RCA Agent</h2>
        <p style="font-size:.82rem;color:var(--text-muted)">Select static incident or simulate live errors:</p>
        <div id="incident-list">Loading incidents...</div>
        <div style="margin-top:8px;padding-top:12px;border-top:1px solid var(--border-color)">
            <p style="font-size:.75rem;color:var(--text-muted);margin-bottom:6px">Phase 4 Approval</p>
            <div id="approval-box" style="font-size:.78rem;color:var(--text-muted)">No pending approvals</div>
        </div>
    </div>
    <div class="main-content">
        <div class="header">
            <div><h1 id="inc-title">Google Cloud RCA Investigation</h1><p id="inc-desc" style="color:var(--text-muted);margin-top:4px">Select an incident or simulate errors below.</p></div>
            <button class="btn btn-green" id="rca-btn" onclick="runLiveRCA()">🧠 Do RCA (Live)</button>
        </div>
        <div class="sim-bar">
            <strong>🧪 Simulate Errors:</strong>
            <button class="sim-btn" onclick="simulate('db-timeout')">DB Timeout</button>
            <button class="sim-btn" onclick="simulate('pool-exhaustion')">Pool Exhaustion</button>
            <button class="sim-btn" onclick="simulate('bad-deployment')">Bad Deployment</button>
            <button class="sim-btn" onclick="simulate('dependency-failure')">Dependency Failure</button>
            <button class="sim-btn" onclick="simulate('traffic-overload')">Traffic Overload</button>
            <button class="sim-btn" onclick="simulate('config-error')">Config Error</button>
            <button class="sim-btn" onclick="simulate('memory-leak')">Memory Leak</button>
            <button class="sim-btn" onclick="simulate('cpu-exhaustion')">CPU Exhaustion</button>
            <button class="sim-btn" onclick="simulate('auth-failure')">Auth Failure</button>
            <button class="sim-btn" onclick="simulate('network-timeout')">Network Timeout</button>
            <button class="sim-btn" onclick="simulate('malformed-payload')">Malformed Input</button>
            <button class="sim-btn" onclick="simulate('rate-limit')">Rate Limit</button>
            <button class="sim-btn btn-red" onclick="clearLogs()">Clear</button>
            <span id="live-status" style="margin-left:auto;font-size:.78rem;color:var(--text-muted)"><span class="status-dot dot-green"></span>Live</span>
        </div>
        <div class="grid">
            <div class="card" style="grid-column: span 2;">
                <div class="card-title">📡 Live Logs <span style="font-size:.75rem;color:var(--text-muted);font-weight:400">— auto-refresh every 3s, click Simulate to inject</span>
                    <button class="sim-btn" id="pause-btn" onclick="togglePause()" style="margin-left:auto">Pause</button>
                </div>
                <div id="log-summary" style="display:flex;flex-wrap:wrap;gap:14px;font-size:.78rem;color:var(--text-muted);margin-bottom:8px;padding:8px 10px;background:#020617;border:1px solid var(--border-color);border-radius:6px">No data yet — simulate an incident.</div>
                <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px;align-items:center;font-size:.78rem">
                    <select id="f-service" onchange="renderLogs()" style="background:#0b1329;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 6px"><option value="">All services</option></select>
                    <select id="f-severity" onchange="renderLogs()" style="background:#0b1329;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 6px"><option value="">All severities</option><option>DEBUG</option><option>INFO</option><option>WARNING</option><option>ERROR</option><option>CRITICAL</option></select>
                    <select id="f-error" onchange="renderLogs()" style="background:#0b1329;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 6px;max-width:220px"><option value="">All error types</option></select>
                    <input id="f-trace" oninput="renderLogs()" placeholder="trace id…" style="background:#0b1329;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 8px;font-size:.78rem;width:150px" />
                    <input id="f-search" oninput="renderLogs()" placeholder="search logs…" style="flex:1;min-width:140px;background:#0b1329;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:4px 8px;font-size:.78rem" />
                </div>
                <div id="live-logs" class="log-panel">Waiting for simulated errors... Click any 🧪 button above.</div>
            </div>
        </div>
        <div id="rca-output" style="display:none;">
            <div class="grid">
                <div class="card"><div class="card-title">🎯 Confirmed Root Cause</div>
                    <div style="margin-bottom:12px;"><span class="badge badge-red" id="rc-category">Category</span> <span class="badge badge-yellow" id="rc-confidence">Confidence</span> <span class="badge badge-green" id="rc-risk">Risk</span></div>
                    <p id="rc-summary" style="line-height:1.6;font-size:.95rem"></p>
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
                        <pre id="cf-diff" style="background:#020617;border:1px solid var(--border-color);border-radius:6px;padding:12px;overflow-x:auto;font-family:'JetBrains Mono',monospace;font-size:.78rem;line-height:1.5;white-space:pre-wrap"></pre>
                        <div id="cf-meta" style="font-size:.8rem;color:var(--text-muted);margin-top:8px"></div>
                    </div>
                    <div id="cf-no-fix" style="display:none" class="item-box"></div>
                    <div id="cf-preflight" style="font-size:.76rem;color:var(--text-muted);margin:8px 0"></div>
                    <div id="cf-lifecycle" style="font-size:.8rem;color:var(--text-muted);margin:8px 0"></div>
                    <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:8px">
                        <input id="cf-msg" placeholder="approval note (optional)…" style="flex:1;min-width:180px;background:#0b1329;color:var(--text-main);border:1px solid var(--border-color);border-radius:4px;padding:7px 10px;font-size:.8rem" />
                        <button class="btn btn-green" id="cf-approve-btn" onclick="approveFixPR()">Approve &amp; Create PR</button>
                        <button class="btn btn-red" onclick="rejectFix()">Reject</button>
                        <button class="sim-btn" onclick="generateFix(true)">Regenerate Fix</button>
                    </div>
                    <div id="cf-pr" style="margin-top:10px"></div>
                    <div id="cf-tests" style="margin-top:8px;font-size:.8rem"></div>
                </div>
            </div>
        </div>
    </div>
<script>
let currentIncident='incident_001_db_timeout.json';
let liveIncidentFile=null;
let liveScenario=null;
let LAST_INCIDENT=null;
let LOGS=[];
let PAUSED=false;
let _lastSumSig='';

async function loadIncidents(){
  const res=await fetch('/api/incidents'); const files=await res.json();
  const c=document.getElementById('incident-list'); c.innerHTML='';
  files.forEach((f,idx)=>{
    const card=document.createElement('div'); card.className='incident-card'+(idx===0?' active':'');
    const title=f.replace('incident_','').replace('.json','').replace(/_/g,' ').toUpperCase();
    card.innerHTML=`<h4>${title}</h4><p>${f}</p>`;
    card.onclick=()=>{document.querySelectorAll('.incident-card').forEach(x=>x.classList.remove('active'));card.classList.add('active');currentIncident=f;liveIncidentFile=null;runRCA();};
    c.appendChild(card);
  }); runRCA();
}
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
  btn.innerHTML='<span class="status-dot dot-red"></span>Error injected!';
  setTimeout(()=>btn.innerHTML='<span class="status-dot dot-green"></span>Live',1800);
  fetchLogs();
}
async function clearLogs(){ await fetch('/api/logs/clear',{method:'POST'}); document.getElementById('live-logs').innerHTML='Logs cleared. Ready for new simulation.'; liveIncidentFile=null; }
let _pollInFlight=false, _lastLogSig='', _lastApprSig='';
function _approvalCard(a, accent){
  const border=accent?'var(--accent-cyan)':'var(--border-color)';
  const pad=accent?'4px 10px':'2px 8px';
  return `<div style="padding:6px;border:1px solid ${border};border-radius:6px;margin-bottom:6px"><strong>${a.action}</strong> ${a.incident_id}<br/>Risk ${a.risk}<br/><input class="appr-msg" data-approval-id="${a.approval_id}" id="msg-${a.approval_id}" placeholder="Add a note (optional) — then click Approve or Reject" style="width:100%;margin-top:6px;padding:6px 8px;border-radius:4px;border:1px solid var(--border-color);background:#0b1329;color:var(--text-main);font-size:.78rem" /><div style="margin-top:6px"><button onclick="sendDecision('${a.approval_id}',true,'${a.action}','${a.incident_id}','${a.risk}')" style="padding:${pad};border-radius:4px;background:var(--accent-green);border:none;color:#fff;cursor:pointer">Approve</button> <button onclick="sendDecision('${a.approval_id}',false,'${a.action}','${a.incident_id}','${a.risk}')" style="margin-left:6px;padding:${pad};border-radius:4px;background:var(--accent-red);border:none;color:#fff;cursor:pointer">Reject</button></div></div>`;
}
function esc(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function _historyCard(a){
  const st=a.status||'UNKNOWN';
  const color=st==='APPROVED'?'var(--accent-green)':(st==='REJECTED'?'var(--accent-red)':'var(--accent-yellow)');
  const when=String(a.decided_at||'').replace('T',' ').slice(0,19);
  const note=a.decided_message?`<div style="margin-top:4px;font-style:italic;color:var(--text-main)">Note: ${esc(a.decided_message)}</div>`:'';
  const by=a.decided_by?`<div>By ${esc(a.decided_by)} at ${esc(when)}</div>`:'';
  return `<div style="padding:6px;border:1px solid var(--border-color);border-left:3px solid ${color};border-radius:6px;margin-bottom:6px;font-size:.76rem;color:var(--text-muted)"><span style="color:${color};font-weight:700">${esc(st)}</span> <strong style="color:var(--text-main)">${esc(a.action)}</strong> ${esc(a.incident_id)}<br/>Risk ${esc(a.risk)}${by}${note}</div>`;
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
        if(d.length){ html+= [...d].reverse().map(a=>_approvalCard(a,false)).join(''); }
        else{ html+='<div style="font-size:.78rem;color:var(--text-muted);margin-bottom:6px">No pending approvals</div>'; }
        if(h.length){ html+='<div style="font-size:.7rem;color:var(--text-muted);margin:8px 0 4px;text-transform:uppercase;letter-spacing:.05em">Decision history</div>'+h.map(a=>_historyCard(a)).join(''); }
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
  const btn=document.getElementById('rca-btn'); btn.disabled=true; btn.innerText='⏳ Investigating...';
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
  btn.disabled=false; btn.innerText='🧠 Do RCA (Live)';
  fetchLogs();
  if(useLive&&data.incident_id){ autoCodeFix(data.incident_id); }
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
async function autoCodeFix(incident_id){
  // Fire-and-forget code investigation right after RCA so the diff panel fills in
  try{
    document.getElementById('codefix-output').style.display='block';
    refreshPreflight();
    document.getElementById('cf-investigation').innerHTML='<span style="color:var(--text-muted);font-size:.85rem">Investigating code…</span>';
    const inv=await (await fetch('/api/incidents/'+incident_id+'/analyze-code',{method:'POST'})).json();
    renderInvestigation(inv);
    await generateFix(false);
  }catch(e){ document.getElementById('cf-investigation').innerHTML='<span style="color:var(--accent-red)">Code investigation failed: '+esc(e.message||e)+'</span>'; }
}
function renderRCA(data){
  const out=document.getElementById('rca-output'); out.style.display='block';
  LAST_INCIDENT=data.incident_id||null;
  document.getElementById('inc-title').innerText="Incident: "+data.incident_id;
  document.getElementById('inc-desc').innerText=`Affected: ${(data.affected_services||[]).join(', ')}`;
  document.getElementById('rc-category').innerText=(data.root_cause_category||'unknown').toUpperCase();
  document.getElementById('rc-confidence').innerText=`${((data.confidence_score||data.confidence||0)*100).toFixed(1)}% CONFIDENCE`;
  document.getElementById('rc-risk').innerText=`RISK: ${data.remediation_risk||data.estimated_risk||'LOW'}`;
  document.getElementById('rc-summary').innerText=data.root_cause||data.recommended_action||'';
  document.getElementById('rc-blast').innerText=data.blast_radius||JSON.stringify(data.blast_radius||'');
  document.getElementById('rc-action').innerText=data.recommended_action||data.expected_effect||'';
  const tBox=document.getElementById('rc-timeline'); tBox.innerHTML=(data.timeline||[]).map(t=>`<div style="font-size:.78rem;padding:4px 0;border-bottom:1px solid var(--border-color)"><strong>${t.timestamp}</strong> [${t.event_type}] ${t.description}</div>`).join('')||'<span style="color:var(--text-muted)">No timeline</span>';
  document.getElementById('additional-checks').innerHTML=(data.additional_checks_required||data.preconditions||[]).map(c=>`<div class="item-box">🔍 ${c}</div>`).join('')||'<p style="color:var(--text-muted)">None</p>';
  document.getElementById('evidence-list').innerHTML=(data.evidence||data.supporting_evidence||[]).map(e=>`<div class="evidence-box"><span style="color:var(--accent-green)">✔</span> ${e}</div>`).join('');
  document.getElementById('contra-list').innerHTML=(data.contradictory_evidence||[]).map(c=>`<div class="evidence-box"><span style="color:var(--accent-red)">✖</span> ${c}</div>`).join('')||'<p style="color:var(--text-muted);font-size:.85rem">None</p>';
  const rb=document.getElementById('remediation-box');
  if(data.remediation_plan||data.approval){ const p=data.remediation_plan||data; const a=data.approval; rb.innerHTML=`<div style="padding:10px;border:1px solid var(--accent-cyan);border-radius:6px;background:#020617"><strong>Remediation:</strong> ${p.recommended_action||p.action} (${p.mitigation_type||''}) Risk ${p.estimated_risk||p.risk}<br/><strong>Rollback:</strong> ${p.rollback_plan||''}<br/>${a?`<strong>Approval:</strong> ${a.approval_id} <em>${a.status}</em>`:''}</div>`; } else { rb.innerHTML='';}
  out.scrollIntoView({behavior:'smooth'});
}
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
      `<div><strong>Reason:</strong> ${esc(p.reasoning_summary)}</div>`+
      `<div><strong>Risk:</strong> ${esc(p.risk)} · <strong>Tests:</strong> ${p.tests_to_run.map(esc).join(', ')}</div>`+
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
  if(job.pr_url){ pr.innerHTML=`<div class="item-box" style="border-left-color:var(--accent-green)"><strong>Branch:</strong> ${esc(job.branch||'')} · <strong>Commit:</strong> ${esc(job.commit||'')} · <strong>PR:</strong> #${job.pr_number||''} <a href="${esc(job.pr_url)}" target="_blank" style="color:var(--accent-cyan)">View Pull Request</a></div>`; }
  else if(job.branch){ pr.innerHTML=`<div class="item-box"><strong>Branch:</strong> ${esc(job.branch)}${job.commit?(' · <strong>Commit:</strong> '+esc(job.commit)):''}</div>`; }
  else{ pr.innerHTML=''; }
  const t=document.getElementById('cf-tests');
  if(job.test_output){ t.innerHTML='<strong>Test Results:</strong><pre style="background:#020617;border:1px solid var(--border-color);border-radius:6px;padding:10px;max-height:220px;overflow:auto;font-size:.75rem;white-space:pre-wrap">'+esc(job.test_output.slice(-2000))+'</pre>'; }
}
setInterval(fetchLogs,3000); window.onload=()=>{loadIncidents();fetchLogs();};
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

    agent = CloudRCAAgent()
    result = await asyncio.to_thread(agent.analyze, file_path)
    return result.model_dump()


# Phase 4: Health, approval, remediation, execution, verification, memory

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
    return req.model_dump()

@app.post("/approvals/{approval_id}/reject")
@app.post("/api/approvals/{approval_id}/reject")
def reject_request(approval_id: str, approver: str = "human-operator", body: dict = None):
    msg = (body or {}).get("message", "") if isinstance(body, dict) else ""
    if isinstance(body, dict) and body.get("approver"):
        approver = body.get("approver")
    req = global_approval_manager.reject(approval_id, approver=approver, message=msg)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    audit_log("APPROVAL_REJECTED", req.incident_id, approver, req.action, req.target_resource, approval_id=approval_id, result=msg)
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
    return {"simulated": True, "scenario": scenario, "incident_id": incident_id,
            "incident_file": incident_file, "logs_injected": len(new_logs),
            "bucket": bucket or "local", "summary": summarize(new_logs)}

@app.post("/api/rca/live")
async def run_live_rca():
    # Fresh investigation from the LIVE log stream (Part 4). Static files only
    # supply deployments/traces/dependencies; counts, rates and latencies come
    # from the actual streamed logs. Scenarios without static files are built
    # purely from live evidence.
    from schemas.evidence import IncidentEvidence
    from tools.live_evidence import merge_static_with_live, build_evidence_from_logs
    scenario = LATEST_SCENARIO
    incident_file = LATEST_SIMULATED_FILE
    live_logs = [l for l in SIMULATED_LOGS
                 if not scenario or l.get("scenario") == scenario] or SIMULATED_LOGS
    if incident_file:
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
    # Heavy workflow in a thread — polls and clicks keep working while it runs
    state, plan, cat = await asyncio.to_thread(_investigate_and_plan, ev)
    approval = global_approval_manager.create_request(
        incident_id=ev.incident_id, action=plan.recommended_action, target_resource=plan.target_resource,
        rationale=plan.expected_effect, root_cause=plan.root_cause, confidence=plan.confidence, risk=plan.estimated_risk.value,
        expected_impact=plan.expected_effect, rollback_plan=plan.rollback_plan
    )
    audit_log("RCA_LIVE", ev.incident_id, "web-user", plan.recommended_action, approval.target_resource, approval_id=approval.approval_id)
    # Merge report + remediation for frontend render
    result = state.final_report.model_dump()
    result["remediation_plan"] = plan.model_dump()
    result["approval"] = approval.model_dump()
    result["timeline"] = [t.model_dump() for t in state.final_report.timeline]
    # add simulated logs hint
    result["live_logs_count"] = len(SIMULATED_LOGS)
    # remember validated RCA for the code-fix pipeline (Part 5+)
    _best_cat, _best_conf = None, 0.0
    for _v in state.validated_hypotheses:
        if _v.accepted:
            _h = next((x for x in state.hypotheses if x.hypothesis_id == _v.hypothesis_id), None)
            if _h and _v.adjusted_confidence >= _best_conf:
                _best_cat, _best_conf = _h.root_cause_category, _v.adjusted_confidence
    LAST_RCA[ev.incident_id] = {
        "root_cause_category": _best_cat or (state.hypotheses[0].root_cause_category if state.hypotheses else "unknown"),
        "root_cause": state.final_report.root_cause,
        "confidence": state.final_report.confidence,
        "supporting_evidence": state.final_report.supporting_evidence,
        "contradictory_evidence": state.final_report.contradictory_evidence,
        "service": ev.service_name,
    }
    return result

# --- Code fix + PR pipeline (Parts 5-15, 19) ---
from schemas.code_fix import FixJob, FixStatus

FIX_JOBS = {}  # incident_id -> {"job": FixJob, "proposal": PatchProposal|None, "approval_id": str|None}
LAST_RCA = {}  # incident_id -> validated RCA summary for code mapping


def _get_rca(incident_id: str) -> dict:
    rca = LAST_RCA.get(incident_id)
    if not rca:
        raise HTTPException(status_code=400, detail=f"No validated RCA for {incident_id}: click 'Do RCA (Live)' first")
    return rca


def _demo_repo() -> str:
    import os as _os
    return _os.getenv("DEMO_APP_PATH") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cloud-rca-demo-app")


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
    return {"fix_status": entry["job"].status.value, "approval": req.model_dump()}


@app.post("/api/incidents/{incident_id}/fix/reject")
def reject_fix(incident_id: str, body: dict = None):
    entry = FIX_JOBS.get(incident_id)
    if not entry or not entry.get("approval_id"):
        raise HTTPException(status_code=404, detail="No pending code fix approval for this incident")
    msg = (body or {}).get("message", "") if isinstance(body, dict) else ""
    req = global_approval_manager.reject(entry["approval_id"], message=msg)
    entry["job"].status = FixStatus.REJECTED
    audit_log("FIX_REJECTED", incident_id, "human-operator", "code_fix_pr",
              req.target_resource, approval_id=req.approval_id, result=msg)
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

# Keep original analyze endpoint

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port)
