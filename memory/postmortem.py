"""
Postmortem report generation
"""
from typing import Dict, Any
from memory.schemas import IncidentMemoryRecord

def generate_postmortem(record: IncidentMemoryRecord) -> Dict[str, Any]:
    timeline_str = "\n".join([f"{e.get('timestamp')} {e.get('description')}" for e in record.timeline])
    return {
        "incident_summary": f"{record.incident_id} on {record.service} - {record.root_cause}",
        "impact": f"Blast radius {record.blast_radius}",
        "timeline": timeline_str,
        "detection": f"Detected via symptoms {record.symptoms}",
        "root_cause": record.root_cause,
        "contributing_factors": record.supporting_evidence,
        "blast_radius": record.blast_radius,
        "remediation": record.remediation,
        "verification": record.verification_result,
        "what_went_well": ["Automated investigation completed", "Critic prevented false RCA"],
        "what_went_wrong": record.rejected_hypotheses,
        "follow_up_actions": ["Review deployment tests", "Adjust pool limits"],
        "preventive_recommendations": ["Add liveness probe", "Increase MAX_SCALE_LIMIT monitoring"],
        "final_status": record.final_status,
    }
