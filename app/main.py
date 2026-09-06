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
import time

app = FastAPI(title="Cloud Incident RCA Agent Dashboard - Phase 4")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Google Cloud Incident Investigation & RCA Agent</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0b1329;
            --card-bg: #151e36;
            --accent-cyan: #06b6d4;
            --accent-purple: #8b5cf6;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #223055;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            display: flex;
            min-height: 100vh;
        }

        .sidebar {
            width: 320px;
            background-color: #080d1c;
            border-right: 1px solid var(--border-color);
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }

        .sidebar h2 {
            font-size: 1.15rem;
            color: var(--accent-cyan);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .incident-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 12px 14px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .incident-card:hover, .incident-card.active {
            border-color: var(--accent-cyan);
            transform: translateY(-2px);
            box-shadow: 0 4px 14px rgba(6, 182, 212, 0.2);
        }
        .incident-card h4 { font-size: 0.88rem; margin-bottom: 4px; }
        .incident-card p { font-size: 0.75rem; color: var(--text-muted); }

        .main-content {
            flex: 1;
            padding: 32px;
            overflow-y: auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }

        .btn {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            color: white;
            border: none;
            padding: 10px 22px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
        }

        .card-title {
            font-size: 1.05rem;
            font-weight: 600;
            margin-bottom: 14px;
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--accent-cyan);
        }

        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-red { background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }
        .badge-yellow { background: rgba(245, 158, 11, 0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }
        .badge-green { background: rgba(16, 185, 129, 0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }

        .item-box {
            background: #0b1329;
            border-left: 4px solid var(--accent-cyan);
            padding: 10px 14px;
            margin-bottom: 8px;
            border-radius: 0 6px 6px 0;
            font-size: 0.88rem;
        }

        .evidence-box {
            background: #0b1329;
            border: 1px solid var(--border-color);
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 8px;
            font-size: 0.85rem;
        }
    </style>
</head>
<body>

    <div class="sidebar">
        <h2>🔍 Cloud RCA Agent</h2>
        <p style="font-size:0.82rem; color:var(--text-muted)">Select an incident scenario to run automated diagnosis:</p>
        <div id="incident-list">Loading incidents...</div>
    </div>

    <div class="main-content">
        <div class="header">
            <div>
                <h1 id="inc-title">Google Cloud RCA Investigation</h1>
                <p id="inc-desc" style="color:var(--text-muted); margin-top:4px">Select an incident from the sidebar.</p>
            </div>
            <button class="btn" onclick="runRCA()">⚡ Run RCA Analysis</button>
        </div>

        <div id="rca-output" style="display:none;">
            <div class="grid">
                <div class="card">
                    <div class="card-title">🎯 Confirmed Root Cause</div>
                    <div style="margin-bottom:12px;">
                        <span class="badge badge-red" id="rc-category">Category</span>
                        <span class="badge badge-yellow" id="rc-confidence">Confidence</span>
                        <span class="badge badge-green" id="rc-risk">Risk</span>
                    </div>
                    <p id="rc-summary" style="line-height:1.6; font-size:0.95rem;"></p>
                    <div style="margin-top:14px; font-size:0.85rem; color:var(--text-muted)">
                        <strong>Blast Radius:</strong> <span id="rc-blast"></span>
                    </div>
                </div>

                <div class="card">
                    <div class="card-title">🛠️ Recommended Action</div>
                    <div class="item-box" id="rc-action" style="border-left-color: var(--accent-green); font-weight: 500;"></div>
                    <div style="margin-top:12px;">
                        <strong style="font-size:0.85rem; color:var(--text-muted);">Additional Checks:</strong>
                        <div id="additional-checks" style="margin-top:6px;"></div>
                    </div>
                </div>
            </div>

            <div class="grid">
                <div class="card">
                    <div class="card-title">📌 Supporting Evidence Cited</div>
                    <div id="evidence-list"></div>
                </div>

                <div class="card">
                    <div class="card-title">✖ Contradictory Evidence Analyzed</div>
                    <div id="contra-list"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentIncident = 'incident_001_db_timeout.json';

        async function loadIncidents() {
            const res = await fetch('/api/incidents');
            const files = await res.json();
            const container = document.getElementById('incident-list');
            container.innerHTML = '';
            files.forEach((f, idx) => {
                const card = document.createElement('div');
                card.className = 'incident-card' + (idx === 0 ? ' active' : '');
                const title = f.replace('incident_', '').replace('.json', '').replace(/_/g, ' ').toUpperCase();
                card.innerHTML = `<h4>${title}</h4><p>${f}</p>`;
                card.onclick = () => {
                    document.querySelectorAll('.incident-card').forEach(c => c.classList.remove('active'));
                    card.classList.add('active');
                    currentIncident = f;
                    runRCA();
                };
                container.appendChild(card);
            });
            runRCA();
        }

        async function runRCA() {
            const output = document.getElementById('rca-output');
            output.style.display = 'none';
            const res = await fetch('/api/analyze/' + currentIncident);
            const data = await res.json();

            document.getElementById('inc-title').innerText = "Incident: " + data.incident_id;
            document.getElementById('inc-desc').innerText = `Affected Services: ${data.affected_services.join(', ')}`;

            document.getElementById('rc-category').innerText = data.root_cause_category.toUpperCase();
            document.getElementById('rc-confidence').innerText = `${(data.confidence_score * 100).toFixed(1)}% CONFIDENCE`;
            document.getElementById('rc-risk').innerText = `RISK: ${data.remediation_risk}`;
            document.getElementById('rc-summary').innerText = data.root_cause;
            document.getElementById('rc-blast').innerText = data.blast_radius;

            document.getElementById('rc-action').innerText = data.recommended_action;

            // Checks
            const chkBox = document.getElementById('additional-checks');
            chkBox.innerHTML = (data.additional_checks_required || []).map(c => `<div class="item-box">🔍 ${c}</div>`).join('') || '<p style="color:var(--text-muted)">None required.</p>';

            // Evidence
            const evBox = document.getElementById('evidence-list');
            evBox.innerHTML = (data.evidence || []).map(e => `
                <div class="evidence-box">
                    <span style="color:var(--accent-green)">✔</span> ${e}
                </div>
            `).join('');

            // Contradictory Evidence
            const contraBox = document.getElementById('contra-list');
            contraBox.innerHTML = (data.contradictory_evidence || []).map(c => `
                <div class="evidence-box">
                    <span style="color:var(--accent-red)">✖</span> ${c}
                </div>
            `).join('') || '<p style="color:var(--text-muted); font-size:0.85rem">No contradictory signals detected.</p>';

            output.style.display = 'block';
        }

        window.onload = loadIncidents;
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
def analyze_incident_api(incident_filename: str):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    file_path = os.path.join(base_dir, "data", "incidents", incident_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Incident file not found")

    agent = CloudRCAAgent()
    result = agent.analyze(file_path)
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
def create_remediation_plan(incident_id: str):
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
    wf = InvestigationWorkflow()
    state = wf.run(ev)
    # Build remediation plan from validated RCA
    rem_agent = RemediationAgent()
    # Use top validated hypothesis category
    cat = None
    if state.validated_hypotheses:
        best = max([v for v in state.validated_hypotheses if v.accepted], key=lambda x: x.adjusted_confidence, default=None)
        if best:
            hyp = next((h for h in state.hypotheses if h.hypothesis_id==best.hypothesis_id), None)
            if hyp:
                cat = hyp.root_cause_category
    plan = rem_agent.plan(ev, state.final_report, validated_category=cat)
    # Create approval request via manager
    approval = global_approval_manager.create_request(
        incident_id=incident_id, action=plan.recommended_action, target_resource=plan.target_resource or f"projects/{ev.project_id}/locations/{ev.region}/services/{ev.service_name}",
        rationale=plan.expected_effect, root_cause=plan.root_cause, confidence=plan.confidence, risk=plan.estimated_risk.value,
        expected_impact=plan.expected_effect, rollback_plan=plan.rollback_plan
    )
    audit_log("REMEDIATION_PLANNED", incident_id, "RemediationAgent", plan.recommended_action, approval.target_resource, before=None, after=plan.model_dump(), approval_id=approval.approval_id)
    return {"remediation_plan": plan.model_dump(), "approval": approval.model_dump()}

@app.get("/approvals/{approval_id}")
def get_approval(approval_id: str):
    req = global_approval_manager.get(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    return req.model_dump()

@app.post("/approvals/{approval_id}/approve")
def approve_request(approval_id: str, approver: str = "human-operator"):
    req = global_approval_manager.approve(approval_id, approver=approver)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    audit_log("APPROVAL_APPROVED", req.incident_id, approver, req.action, req.target_resource, approval_id=approval_id)
    return req.model_dump()

@app.post("/approvals/{approval_id}/reject")
def reject_request(approval_id: str, approver: str = "human-operator"):
    req = global_approval_manager.reject(approval_id, approver=approver)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    audit_log("APPROVAL_REJECTED", req.incident_id, approver, req.action, req.target_resource, approval_id=approval_id)
    return req.model_dump()

@app.post("/approvals/{approval_id}/cancel")
def cancel_request(approval_id: str):
    req = global_approval_manager.cancel(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    audit_log("APPROVAL_CANCELLED", req.incident_id, "system", req.action, req.target_resource, approval_id=approval_id)
    return req.model_dump()

@app.post("/approvals/{approval_id}/execute")
def execute_approval(approval_id: str, action_params: dict = None):
    action_params = action_params or {}
    req = global_approval_manager.get(approval_id)
    if not req:
        raise HTTPException(status_code=404, detail="Approval not found")
    executor = ExecutorAgent()
    result = executor.execute(req, action_params)
    audit_log("EXECUTION", req.incident_id, "ExecutorAgent", req.action, req.target_resource, before=result.before_state, after=result.after_state, approval_id=approval_id, result=result.status.value)
    # Verification step (simple metrics stub)
    verifier = VerificationAgent()
    # Use dummy metrics before/after for demo; in prod fetch real metrics
    metrics_before = {"error_rate_pct": 20, "latency_p95_ms": 3000}
    metrics_after = {"error_rate_pct": 0.5 if result.status.value=="SUCCESS" else 18, "latency_p95_ms": 180 if result.status.value=="SUCCESS" else 2900}
    verification = verifier.verify(req.incident_id, result, metrics_before, metrics_after)
    audit_log("VERIFICATION", req.incident_id, "VerificationAgent", verification.verification_status.value, req.target_resource, before=metrics_before, after=metrics_after)
    # Store memory
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
    return {"execution": result.model_dump(), "verification": verification.model_dump(), "postmortem": postmortem}

# Keep original analyze endpoint

if __name__ == "__main__":
    import os
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port)
