"""
Deployment Investigation Agent - analyzes Cloud Run revision evidence.
Guardrail: only deployment_tools allowed.
Must report temporal proximity, NOT causation.
"""
from datetime import datetime, timezone
from typing import List, Optional
from schemas.evidence import IncidentEvidence
from schemas.findings import AgentFinding, FindingType, EvidenceStrength


def _parse_iso(ts: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

class DeploymentInvestigationAgent:
    agent_name = "Deployment Investigation Agent"
    ALLOWED_FIELDS = {"recent_deployments", "revision_name"}

    def investigate(self, evidence: IncidentEvidence) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        revs = evidence.recent_deployments or []
        incident_start = _parse_iso(evidence.start_time)
        service = evidence.service_name

        if not revs:
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.DEPLOYMENT_CORRELATION,
                evidence_strength=EvidenceStrength.MISSING_EVIDENCE,
                summary="No recent deployment records available in investigation window",
                supporting_evidence=[],
                confidence=0.50,
                missing_information=["Deployment revision history unavailable - cannot assess temporal correlation"],
                affected_service=service,
            ))
            return findings

        # Find most recent revision before incident
        # Assume list sorted newest first (as per deployment_tools)
        for rev in revs:
            rev_name = rev.get("revision_name", "unknown")
            deployed_at_str = rev.get("deployed_at") or rev.get("creation_time") or rev.get("creationTime")
            deployed_at = _parse_iso(deployed_at_str) if deployed_at_str else None
            traffic = rev.get("traffic_percent", rev.get("traffic", 100))
            if deployed_at and incident_start:
                delta_min = (incident_start - deployed_at).total_seconds() / 60.0
                # Must report: "Deployment occurred X minutes before incident" - exact phrasing required
                if delta_min >= 0:
                    findings.append(AgentFinding(
                        agent_name=self.agent_name,
                        finding_type=FindingType.DEPLOYMENT_CORRELATION,
                        evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                        summary=f"Revision {rev_name} deployed at {deployed_at_str} - {int(delta_min)} minutes before incident start at {evidence.start_time}",
                        supporting_evidence=[
                            f"Revision: {rev_name}",
                            f"Deployed: {deployed_at_str}",
                            f"Incident start: {evidence.start_time}",
                            f"Time difference: {int(delta_min)} minutes",
                            f"Traffic split: {traffic}% on {rev_name}",
                        ],
                        confidence=0.90 if 0 <= delta_min <= 15 else 0.65,
                        affected_service=service,
                        timestamp_range={"deployed_at": deployed_at_str, "incident_start": evidence.start_time},
                    ))
                    # Explicitly note: temporal correlation is not proof
                    if 0 <= delta_min <= 15:
                        findings[-1].summary += " (temporal proximity increases suspicion but is not proof of causation)"
                    # Traffic split observation
                    if traffic == 100:
                        findings.append(AgentFinding(
                            agent_name=self.agent_name,
                            finding_type=FindingType.DEPLOYMENT_CORRELATION,
                            evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                            summary=f"Revision {rev_name} received 100% traffic allocation",
                            supporting_evidence=[f"Traffic 100% on {rev_name}"],
                            confidence=0.88,
                            affected_service=service,
                        ))
                    break
                else:
                    findings.append(AgentFinding(
                        agent_name=self.agent_name,
                        finding_type=FindingType.DEPLOYMENT_CORRELATION,
                        evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                        summary=f"Revision {rev_name} deployed AFTER incident start ({deployed_at_str} vs {evidence.start_time}) - cannot be cause",
                        supporting_evidence=[f"Revision {rev_name} at {deployed_at_str} is after incident"],
                        confidence=0.85,
                        affected_service=service,
                    ))
            else:
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPLOYMENT_CORRELATION,
                    evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                    summary=f"Revision {rev_name} found but deployment timestamp unavailable or unparsable ({deployed_at_str})",
                    supporting_evidence=[f"Revision {rev_name}, deployed_at {deployed_at_str}"],
                    confidence=0.55,
                    missing_information=["Deployment timestamp parsing failed"],
                ))

        # Check previous healthy revision
        if len(revs) >= 2:
            prev = revs[1]
            prev_name = prev.get("revision_name")
            prev_status = prev.get("status", "unknown")
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.DEPLOYMENT_CORRELATION,
                evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                summary=f"Previous revision {prev_name} status {prev_status} - comparison baseline for regression analysis",
                supporting_evidence=[f"Previous revision {prev_name} status {prev_status}"],
                confidence=0.70,
                affected_service=service,
            ))

        # Configuration diff placeholder - would need deployment_tools.compare_revisions
        # We expose observation without inventing diff
        if len(revs) >= 2:
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.DEPLOYMENT_CORRELATION,
                evidence_strength=EvidenceStrength.MISSING_EVIDENCE,
                summary="Revision configuration diff requires deployment_tools.compare_revisions - image and env var changes not yet inspected",
                supporting_evidence=[],
                confidence=0.45,
                missing_information=["Container image and env var diff between current and previous revision not yet compared"],
            ))

        return findings
