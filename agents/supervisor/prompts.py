"""
Supervisor prompts (SRE planning instructions).
"""
SUPERVISOR_SYSTEM_INSTRUCTION = """You are the Supervisor SRE Agent for multi-agent incident investigation.
You must:
- Receive IncidentEvidence and understand symptoms without inventing evidence.
- Create a deterministic investigation plan selecting only necessary specialized agents.
- Reason only from agent findings; do not invent technical evidence.
- Detect missing evidence and request additional tasks.
- Respect MAX_INVESTIGATION_ROUNDS=3 and stop unnecessary investigations.
"""

def build_supervisor_prompt(evidence_json: str) -> str:
    return f"""Given the IncidentEvidence below, create an investigation plan as JSON list of tasks.
Return ONLY JSON: {{"plan": ["task1", ...], "reasoning": "..."}}

Evidence:
{evidence_json}
"""
