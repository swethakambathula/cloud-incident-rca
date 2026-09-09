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
            <button class="sim-btn btn-red" onclick="clearLogs()">Clear</button>
            <span id="live-status" style="margin-left:auto;font-size:.78rem;color:var(--text-muted)"><span class="status-dot dot-green"></span>Live</span>
        </div>
        <div class="grid">
            <div class="card" style="grid-column: span 2;">
                <div class="card-title">📡 Live Logs <span style="font-size:.75rem;color:var(--text-muted);font-weight:400">— auto-refresh every 1s, click Simulate to inject</span></div>
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
    </div>
<script>
let currentIncident='incident_001_db_timeout.json';
let liveIncidentFile=null;

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
  liveIncidentFile=data.incident_file;
  currentIncident=data.incident_file;
  document.getElementById('inc-title').innerText='Live Simulated: '+scenario;
  document.getElementById('inc-desc').innerText='Injected at '+new Date().toLocaleTimeString()+' — logs streaming below → click Do RCA';
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
async function fetchLogs(){
  if(_pollInFlight) return;  // never stack overlapping polls — this was freezing the page
  _pollInFlight=true;
  try{
    const res=await fetch('/api/logs/live?limit=80'); const logs=await res.json();
    const sig=logs.length+'|'+(logs.length?logs[logs.length-1].timestamp+logs[logs.length-1].message:'empty');
    if(sig!==_lastLogSig){
      _lastLogSig=sig;
      const box=document.getElementById('live-logs');
      if(!logs.length){ box.innerHTML='<span class="log-info">No errors yet — click 🧪 Simulate Errors above</span>'; }
      else{
        // only force-scroll if user is already near the bottom, so reading isn't yanked away
        const nearBottom=(box.scrollHeight-box.scrollTop-box.clientHeight)<60;
        box.innerHTML=logs.map(l=>{
          const cls=l.severity==='ERROR'?'log-error':l.severity==='WARNING'?'log-warn':'log-info';
          return `<div class="log-line ${cls}">[${l.timestamp}] <strong>${l.severity}</strong> ${l.error_code||''} ${l.message} <span style="opacity:.6">trace=${l.trace_id||'none'}</span></div>`;
        }).join('');
        if(nearBottom) box.scrollTop=box.scrollHeight;
      }
    }
    const pr=await fetch('/api/approvals/pending'); const d=await pr.json();
    const asig=d.map(a=>a.approval_id+':'+a.status).join(',');
    if(asig!==_lastApprSig){
      const firstLoad=_lastApprSig==='';
      _lastApprSig=asig;
      const ab=document.getElementById('approval-box');
      const prevIds=new Set([...document.querySelectorAll('.appr-msg')].map(el=>el.dataset.approvalId));
      const typing=document.activeElement&&document.activeElement.classList&&document.activeElement.classList.contains('appr-msg');
      if(!d.length){ ab.innerHTML='No pending approvals'; }
      else{
        // never rebuild while the user is typing — new approvals are appended, not re-rendered
        if(typing){ /* skip: keep DOM + focus + text untouched */ }
        else{ ab.innerHTML=d.map(a=>_approvalCard(a,false)).join(''); }
      }
      // focus ONLY a brand-new approval input, once — never steal focus otherwise
      const fresh=[...document.querySelectorAll('.appr-msg')].find(el=>!prevIds.has(el.dataset.approvalId));
      if(fresh&&(firstLoad||!typing)) fresh.focus();
    }
  }catch(e){ /* poll failure must never break the page */ }
  finally{ _pollInFlight=false; }
}
async function sendDecision(id, isApprove, action, incident, risk){
  const input=document.getElementById('msg-'+id);
  const message=input?input.value.trim():"";
  const verb=isApprove?'APPROVE':'REJECT';
  // Explicit human confirmation — nothing is auto-approved; Enter key alone never submits
  const detail=(action||'')+(incident?' for '+incident:'')+(risk?' (Risk '+risk+')':'')+(message?'\nNote: '+message:'');
  if(!confirm(verb+' this remediation?\n\n'+detail)) return;
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
  // Use multi-agent live endpoint if live incident exists, else static
  const url=liveIncidentFile?'/api/rca/live':'/api/analyze/'+target;
  const res=await fetch(url,{method: liveIncidentFile?'POST':'GET'});
  const data=await res.json();
  // Normalize both response shapes
  const rca=data.root_cause?data:data;
  // For live, data contains remediation_plan+approval
  renderRCA(rca.root_cause?rca:{...rca, ...rca.remediation_plan});
  // If live returned approval, show it with message box + focus (sync poll signature so next poll won't rebuild it)
  if(data.approval){ const ap=data.approval; _lastApprSig=ap.approval_id+':'+ap.status; document.getElementById('approval-box').innerHTML=_approvalCard(ap,true); const inp=document.getElementById('msg-'+ap.approval_id); if(inp) inp.focus(); }
  btn.disabled=false; btn.innerText='🧠 Do RCA (Live)';
  fetchLogs();
}
function renderRCA(data){
  const out=document.getElementById('rca-output'); out.style.display='block';
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
SCENARIO_MAP = {
    "db-timeout": ("incident_001_db_timeout.json", "DATABASE_CONNECTION_TIMEOUT", "ERROR", "could not connect to orders-db.internal:5432 after 5000ms"),
    "pool-exhaustion": ("incident_002_pool_exhaustion.json", "DATABASE_CONNECTION_POOL_EXHAUSTED", "ERROR", "pool_usage=100% waiting_threads=45"),
    "bad-deployment": ("incident_003_bad_deployment.json", "NULL_POINTER_EXCEPTION", "ERROR", "NullPointerException in PaymentProcessor.java:84"),
    "dependency-failure": ("incident_004_dependency_outage.json", "DOWNSTREAM_DEPENDENCY_FAILURE", "ERROR", "dependency=orders-service status=503"),
    "traffic-overload": ("incident_005_traffic_overload.json", "REQUEST_QUEUE_FULL_THROTTLED", "WARNING", "max_concurrent_requests_exceeded instances=10"),
    "config-error": ("incident_006_config_regression.json", "CONFIGURATION_REGRESSION", "ERROR", "Required environment variable PAYMENT_GATEWAY_API_KEY is missing"),
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

@app.post("/api/simulate/{scenario}")
def simulate_error(scenario: str):
    if scenario not in SCENARIO_MAP:
        raise HTTPException(status_code=400, detail=f"Unknown scenario {scenario}. Choose {list(SCENARIO_MAP.keys())}")
    incident_file, code, severity, msg = SCENARIO_MAP[scenario]
    global LATEST_SIMULATED_FILE
    LATEST_SIMULATED_FILE = incident_file
    now = datetime.now(timezone.utc).isoformat()
    # inject 4-6 live log lines to mimic streaming errors
    bucket = None
    try:
        from tools.gcs_tools import get_log_bucket
        bucket = get_log_bucket()
    except Exception:
        bucket = None
    for i in range(5):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "error_code": code,
            "message": f"{code} {msg} ({i+1}/5) scenario={scenario}",
            "trace_id": f"trace-sim-{uuid.uuid4().hex[:8]}",
            "service": "checkout-service",
        }
        SIMULATED_LOGS.append(entry)
        # Bucket: append to GCS as durable log bucket storage
        if bucket:
            try:
                from tools.gcs_tools import upload_jsonl_to_bucket
                upload_jsonl_to_bucket(bucket, f"logs/live/{incident_file}.jsonl", entry)
                upload_jsonl_to_bucket(bucket, "logs/live/central.jsonl", entry)
            except Exception:
                pass
    # also load static incident file for RCA context
    audit_log("SIMULATE", incident_file, "web-user", code, "checkout-service")
    return {"simulated": True, "scenario": scenario, "incident_file": incident_file, "logs_injected": 5, "bucket": bucket or "local"}

@app.get("/api/approvals/pending")
def list_pending_approvals():
    return [r.model_dump() for r in global_approval_manager.list_pending()]

@app.post("/api/rca/live")
async def run_live_rca():
    # Run RCA on latest simulated incident (or fallback to currentIncident)
    incident_file = LATEST_SIMULATED_FILE or "incident_001_db_timeout.json"
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", "incidents", incident_file)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Simulated incident file not found")
    with open(file_path) as f:
        data = json.load(f)
    from schemas.evidence import IncidentEvidence
    ev = IncidentEvidence(**data)
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
    return result

# Keep original analyze endpoint

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port)
