"""
Final Incident Report Agent - generates structured IncidentReport + readable summary.
Deterministic timeline from timestamped evidence (not invented).
"""
from datetime import datetime, timezone
from typing import List
from schemas.report import IncidentReport, BlastRadiusResult, TimelineEvent
from schemas.validation import HypothesisValidation
from schemas.findings import KnowledgeFinding
from schemas.hypothesis import RootCauseHypothesis
from orchestration.state import InvestigationState


def _parse_iso(ts: str):
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None

class ReportAgent:
    agent_name = "Final Incident Report Agent"

    def build_timeline(self, state: InvestigationState) -> List[TimelineEvent]:
        evidence = state.incident_evidence
        events: List[TimelineEvent] = []
        # Deployments
        for rev in evidence.recent_deployments:
            ts = rev.get("deployed_at") or rev.get("creation_time")
            if ts:
                events.append(TimelineEvent(
                    timestamp=ts,
                    event_type="DEPLOYMENT",
                    description=f"Cloud Run revision {rev.get('revision_name')} deployed (traffic {rev.get('traffic_percent', rev.get('traffic', 'unknown'))}%)",
                    source="cloud_run",
                ))
        # First error from raw_evidence
        for re in evidence.raw_evidence:
            ts = re.get("timestamp")
            if ts:
                msg = re.get("summary") or re.get("log") or re.get("message") or str(re)[:120]
                # Infer type
                etype = "ERROR_SPIKE"
                if "timeout" in msg.lower():
                    etype = "ERROR_SPIKE"
                events.append(TimelineEvent(
                    timestamp=ts,
                    event_type=etype,
                    description=msg[:180],
                    source="logging",
                ))
        # Latency increase
        lat = evidence.latency or {}
        if lat.get("severity") in ("WARNING","CRITICAL"):
            # Use incident start as proxy for latency spike
            events.append(TimelineEvent(
                timestamp=evidence.start_time,
                event_type="LATENCY_INCREASE",
                description=f"p95 latency increased to {lat.get('incident_p95_ms', lat.get('incident'))}ms",
                source="monitoring",
            ))
        # HTTP 500 rate
        rc = evidence.request_count or {}
        err_pct = rc.get("error_rate_pct")
        if err_pct and err_pct >= 5:
            events.append(TimelineEvent(
                timestamp=evidence.start_time,
                event_type="ALERT",
                description=f"HTTP 500 rate rose to {err_pct}%",
                source="monitoring",
            ))
        # Sort deterministically by timestamp
        def sort_key(e):
            dt = _parse_iso(e.timestamp)
            return dt if dt else datetime.max.replace(tzinfo=timezone.utc)
        events.sort(key=sort_key)
        # Deduplicate same timestamp+description
        seen = set()
        deduped = []
        for e in events:
            k = e.timestamp + e.description
            if k not in seen:
                seen.add(k)
                deduped.append(e)
        return deduped[:10]

    def generate(self, state: InvestigationState) -> IncidentReport:
        evidence = state.incident_evidence
        # Determine best hypothesis
        validated = state.validated_hypotheses
        # Choose highest adjusted_confidence accepted
        accepted = [v for v in validated if v.accepted]
        if accepted:
            best_val = max(accepted, key=lambda v: v.adjusted_confidence)
            # Find corresponding hypothesis
            best_hyp = next((h for h in state.hypotheses if h.hypothesis_id == best_val.hypothesis_id), None)
        else:
            # No accepted, pick highest confidence hypothesis but mark low
            best_val = max(validated, key=lambda v: v.adjusted_confidence) if validated else None
            best_hyp = next((h for h in state.hypotheses if h.hypothesis_id == best_val.hypothesis_id), state.hypotheses[0] if state.hypotheses else None) if best_val else (state.hypotheses[0] if state.hypotheses else None)

        if best_hyp:
            root_cause = best_hyp.root_cause
            confidence = best_val.adjusted_confidence if best_val else best_hyp.confidence_score
            supporting = best_hyp.supporting_evidence
            contradictory = best_hyp.contradictory_evidence + (best_val.contradictions if best_val else [])
        else:
            root_cause = "Unknown / needs more evidence"
            confidence = 0.30
            supporting = []
            contradictory = []

        # Blast radius
        blast = state.blast_radius
        if not blast:
            # fallback minimal
            blast = BlastRadiusResult(
                primary_service=evidence.service_name,
                affected_services=[evidence.service_name],
                affected_endpoints=evidence.blast_radius.get("affected_endpoints", ["/unknown"]) if isinstance(evidence.blast_radius, dict) else ["/unknown"],
                region=evidence.region or "us-central1",
                affected_revision=evidence.revision_name,
                dependency_impact=[],
                estimated_scope=f"Impact on {evidence.service_name}",
                classification="SERVICE_LEVEL",
                evidence=["Evidence from incident evidence"],
            )

        timeline = self.build_timeline(state)

        # Gather histories
        similar = state.knowledge_findings

        # Gather validated vs rejected
        rejected = state.rejected_hypotheses

        # Recommended action based on root cause
        action_map = {
            "database_connectivity": "Verify database host reachability, VPC connector health, and firewall port 5432",
            "connection_pool_exhaustion": "Increase pool max size, fix connection leaks, restart affected instances",
            "faulty_revision": f"Review {evidence.revision_name or 'latest revision'} diff and prepare rollback pending human approval",
            "dependency_failure": "Check downstream service health, logs, and autoscaling; review circuit breaker",
            "traffic_overload": "Increase max-instances and enable Cloud Armor rate limiting",
            "configuration_regression": "Restore missing env var/secret in Cloud Run spec and redeploy",
        }
        cat = best_hyp.root_cause_category if best_hyp else "unknown"
        recommended = action_map.get(cat, "Collect additional telemetry and consult SRE on-call")

        # Missing evidence
        missing = list(state.missing_evidence)

        # Investigation summary readable
        inv_summary = (
            f"Investigation of {evidence.incident_id} examined {len(state.agent_findings)} findings across "
            f"{len(similar)} knowledge sources, generated {len(state.hypotheses)} hypotheses, "
            f"validated {len(validated)} with {len(accepted)} accepted. Blast radius {blast.classification} on {blast.primary_service}."
        )

        report = IncidentReport(
            incident_id=evidence.incident_id,
            severity=evidence.severity,
            start_time=evidence.start_time,
            end_time=evidence.end_time,
            affected_services=blast.affected_services,
            affected_endpoints=blast.affected_endpoints,
            primary_symptoms=evidence.symptoms[:5],
            timeline=timeline,
            root_cause=root_cause,
            confidence=round(min(confidence, 0.99), 3),
            supporting_evidence=supporting[:8],
            contradictory_evidence=contradictory[:6],
            validated_hypotheses=validated,
            rejected_hypotheses=rejected,
            blast_radius=blast,
            similar_historical_incidents=similar[:3],
            recommended_next_action=recommended,
            missing_evidence=missing[:6],
            investigation_summary=inv_summary,
        )
        return report

    def render_text(self, report: IncidentReport) -> str:
        lines = []
        lines.append(f"INCIDENT: {report.incident_id}")
        lines.append(f"Severity: {report.severity}")
        lines.append(f"Affected Service: {', '.join(report.affected_services)}")
        lines.append(f"Root Cause: {report.root_cause}")
        lines.append(f"Confidence: {report.confidence:.2f}")
        lines.append("Supporting Evidence:")
        for e in report.supporting_evidence:
            lines.append(f"  • {e}")
        lines.append("Contradictory Evidence:")
        for ce in report.contradictory_evidence:
            lines.append(f"  • {ce}")
        lines.append(f"Blast Radius: {report.blast_radius.classification} - {report.blast_radius.estimated_scope}")
        lines.append(f"Recommended Action: {report.recommended_next_action}")
        lines.append("Timeline:")
        for te in report.timeline:
            lines.append(f"  {te.timestamp} [{te.event_type}] {te.description}")
        if report.missing_evidence:
            lines.append("Missing Evidence:")
            for m in report.missing_evidence:
                lines.append(f"  - {m}")
        return "\n".join(lines)
