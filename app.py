"""
Interactive Web Dashboard for Cloud Incident RCA Agent.
Serves a modern, dark-mode visual RCA dashboard.
"""
import os
import glob
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from agents.rca_agent.agent import CloudRCAAgent
import uvicorn

app = FastAPI(title="Cloud Incident RCA Agent Dashboard")

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Incident RCA Agent</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0f172a;
            --card-bg: #1e293b;
            --accent-cyan: #06b6d4;
            --accent-purple: #8b5cf6;
            --accent-red: #ef4444;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
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
            width: 300px;
            background-color: #0b1329;
            border-right: 1px solid var(--border-color);
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 20px;
        }

        .sidebar h2 {
            font-size: 1.2rem;
            color: var(--accent-cyan);
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .incident-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            padding: 14px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .incident-card:hover, .incident-card.active {
            border-color: var(--accent-cyan);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.15);
        }
        .incident-card h4 { font-size: 0.95rem; margin-bottom: 6px; }
        .incident-card p { font-size: 0.8rem; color: var(--text-muted); }

        .main-content {
            flex: 1;
            padding: 32px;
            overflow-y: auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 28px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--border-color);
        }

        .btn {
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-purple));
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .btn:hover { opacity: 0.9; }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 24px;
            margin-bottom: 24px;
        }

        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 16px;
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

        .causal-step {
            background: #151e2e;
            border-left: 4px solid var(--accent-cyan);
            padding: 12px 16px;
            margin-bottom: 10px;
            border-radius: 0 6px 6px 0;
            font-size: 0.9rem;
        }

        .evidence-item {
            background: #0f172a;
            border: 1px solid var(--border-color);
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
        }

        pre {
            background: #090d16;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            color: var(--accent-green);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            margin-top: 8px;
        }
    </style>
</head>
<body>

    <div class="sidebar">
        <h2>🔍 Cloud RCA Agent</h2>
        <p style="font-size:0.85rem; color:var(--text-muted)">Select an incident scenario to run automated Root Cause Analysis:</p>
        <div id="incident-list">Loading incidents...</div>
    </div>

    <div class="main-content">
        <div class="header">
            <div>
                <h1 id="inc-title">Cloud Incident Diagnosis</h1>
                <p id="inc-desc" style="color:var(--text-muted); margin-top:4px">Select an incident from the sidebar.</p>
            </div>
            <button class="btn" onclick="runRCA()">⚡ Run RCA Analysis</button>
        </div>

        <div id="rca-output" style="display:none;">
            <div class="grid">
                <div class="card">
                    <div class="card-title">🎯 Primary Root Cause</div>
                    <div style="margin-bottom:12px;">
                        <span class="badge badge-red" id="rc-component">Component</span>
                        <span class="badge badge-yellow" id="rc-confidence">Confidence</span>
                    </div>
                    <p id="rc-summary" style="line-height:1.6; font-size:0.95rem;"></p>
                </div>

                <div class="card">
                    <div class="card-title">🔗 Causal Chain</div>
                    <div id="causal-chain-list"></div>
                </div>
            </div>

            <div class="grid">
                <div class="card">
                    <div class="card-title">📌 Key Evidence Log Snippets</div>
                    <div id="evidence-list"></div>
                </div>

                <div class="card">
                    <div class="card-title">🛠️ Remediation Plan</div>
                    <div id="remediation-list"></div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentIncident = 'incident_001_db_pool.json';

        async function loadIncidents() {
            const res = await fetch('/api/incidents');
            const files = await res.json();
            const container = document.getElementById('incident-list');
            container.innerHTML = '';
            files.forEach((f, idx) => {
                const card = document.createElement('div');
                card.className = 'incident-card' + (idx === 0 ? ' active' : '');
                card.innerHTML = `<h4>${f.replace('incident_', '').replace('.json', '').replace(/_/g, ' ').toUpperCase()}</h4><p>${f}</p>`;
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

            document.getElementById('inc-title').innerText = data.title;
            document.getElementById('inc-desc').innerText = `Incident ID: ${data.incident_id} | Services: ${data.root_cause_component}`;

            document.getElementById('rc-component').innerText = data.root_cause_component;
            document.getElementById('rc-confidence').innerText = `${(data.confidence_score * 100).toFixed(1)}% CONFIDENCE`;
            document.getElementById('rc-summary').innerText = data.root_cause_summary;

            // Causal Chain
            const chainBox = document.getElementById('causal-chain-list');
            chainBox.innerHTML = data.causal_chain.map((c, i) => `<div class="causal-step">Step ${i+1}: ${c}</div>`).join('');

            // Evidence
            const evBox = document.getElementById('evidence-list');
            evBox.innerHTML = data.evidence.map(e => `
                <div class="evidence-item">
                    <strong style="color:var(--accent-yellow)">[${e.id}] ${e.source_service}</strong> (${e.type})
                    <div style="margin-top:4px; color:var(--text-muted);">${e.description}</div>
                </div>
            `).join('');

            // Remediation
            const remBox = document.getElementById('remediation-list');
            remBox.innerHTML = data.remediation_steps.map(r => `
                <div style="margin-bottom:12px;">
                    <strong>Step ${r.step_number}: ${r.action}</strong>
                    ${r.command_or_config ? `<pre>${r.command_or_config}</pre>` : ''}
                </div>
            `).join('');

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
    base_dir = os.path.dirname(os.path.abspath(__file__))
    inc_dir = os.path.join(base_dir, "data", "incidents")
    files = [os.path.basename(p) for p in glob.glob(os.path.join(inc_dir, "*.json"))]
    return sorted(files)

@app.get("/api/analyze/{incident_filename}")
def analyze_incident_api(incident_filename: str):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(base_dir, "data", "incidents", incident_filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Incident file not found")

    agent = CloudRCAAgent()
    result = agent.analyze_incident(file_path)
    return result.dict()

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
