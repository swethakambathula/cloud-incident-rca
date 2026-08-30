# 🔍 Cloud Incident Root Cause Analysis (RCA) Agent

A local, Python-based agent that automatically analyzes cloud infrastructure log files, extracts key evidence, builds causal timeline chains, isolates primary root causes, and generates actionable remediation plans.

---

## 🌟 Key Features

- **Multi-Format Log Parsing**: Parses JSON CloudWatch/K8s logs, Syslog, Python stack tracebacks, Nginx access logs, and plain text.
- **Automated Evidence Synthesis**: Ranks log anomalies, error cascades, and system events by relevance score.
- **Causal Graph & Timeline**: Merges multi-service event logs into a unified chronological causal timeline.
- **Zero-Dependency Local Engine + LLM Bridge**: Operates deterministically out-of-the-box locally, with support for OpenAI, Gemini, Anthropic, or local Ollama LLMs via `.env`.
- **Accuracy Evaluation Benchmark**: Built-in evaluation framework comparing RCA results against golden ground-truth test cases.
- **Dual Interfaces**:
  - **CLI Runner**: `python main.py` with rich color-coded terminal tree outputs.
  - **Web Dashboard**: Modern dark-mode web dashboard (`python app.py`) with interactive incident selection and visual causal graph cards.

---

## 📁 Repository Architecture

```
cloud-incident-rca/
├── agents/
│   └── rca_agent/
│       ├── agent.py               # Core CloudRCAAgent class
│       ├── prompts.py             # Reasoning prompt templates
│       └── schemas.py             # Pydantic models for LogEntry, Evidence, RCAResult
├── data/
│   ├── incidents/                 # Incident metadata JSON files
│   ├── logs/                      # Raw log files (app.log, sys.log, k8s.log)
│   └── expected_rcas/             # Ground truth reference RCA results
├── tools/
│   ├── log_parser.py              # Multiformat log ingestion & timestamp normalizer
│   └── evidence_extractor.py     # Anomaly detector & evidence ranker
├── evaluation/
│   ├── golden_cases.json          # Benchmark dataset
│   └── test_rca_accuracy.py       # Benchmark precision/recall evaluator
├── tests/                         # Unit tests (Pytest)
├── main.py                        # CLI runner
├── app.py                         # Web UI FastAPI Server
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Installation

```bash
cd cloud-incident-rca
pip install -r requirements.txt
```

### 2. Run CLI RCA Analysis

Run RCA on default or custom incident files:

```bash
python main.py --incident data/incidents/incident_001_db_pool.json
```

Output includes:
- **Root Cause Component & Summary**
- **Confidence Score**
- **Causal Timeline Tree**
- **Ranked Evidence Log Snippets**
- **Actionable Remediation Commands**

### 3. Launch Interactive Web Dashboard

```bash
python app.py
```

Open `http://localhost:8000` in your web browser to explore interactive incident diagnosis!

---

## 📊 Run Accuracy Benchmark Evaluation

Evaluate the agent against golden test cases:

```bash
python -m evaluation.test_rca_accuracy
```

---

## 🧪 Run Unit Tests

```bash
pytest tests/
```
