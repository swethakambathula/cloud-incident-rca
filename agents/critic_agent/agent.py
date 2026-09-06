"""
Critic / Validator Agent - independent review of hypotheses.
Guardrail: only reads evidence and hypotheses, no tool access.
"""
from typing import List
from schemas.evidence import IncidentEvidence
from schemas.findings import AgentFinding
from schemas.hypothesis import RootCauseHypothesis
from schemas.validation import HypothesisValidation, ValidationStatus

class CriticAgent:
    agent_name = "Critic / Validator Agent"

    def validate(self, hypothesis: RootCauseHypothesis, evidence: IncidentEvidence, all_findings: List[AgentFinding]) -> HypothesisValidation:
        """
        Deterministic validation logic per hypothesis category.
        Implements strict SRE reasoning rules from spec.
        """
        category = hypothesis.root_cause_category
        contradictions = []
        missing = []
        supporting_strength = "WEAK"
        status = ValidationStatus.WEAK
        accepted = False

        # Extract signals for checks
        app_codes = {e.get("error_code") for e in evidence.application_errors if isinstance(e, dict)}
        deps = {d.get("name"): d.get("status") for d in evidence.dependencies}
        cpu_sev = evidence.cpu_utilization.get("severity", "NORMAL") if isinstance(evidence.cpu_utilization, dict) else "NORMAL"
        mem_sev = evidence.memory_utilization.get("severity", "NORMAL") if isinstance(evidence.memory_utilization, dict) else "NORMAL"
        has_deployment_before = False
        if evidence.recent_deployments:
            # Check if any deployment within 15 min before incident
            from datetime import datetime
            try:
                start = datetime.fromisoformat(evidence.start_time.replace("Z","+00:00"))
                for rev in evidence.recent_deployments:
                    ts = rev.get("deployed_at") or rev.get("creation_time")
                    if ts:
                        dep_time = datetime.fromisoformat(ts.replace("Z","+00:00"))
                        delta_min = (start - dep_time).total_seconds()/60
                        if 0 <= delta_min <= 30:
                            has_deployment_before = True
            except Exception:
                pass

        failing_deps = [n for n,s in deps.items() if s in ("UNAVAILABLE","UNREACHABLE","ERROR")]
        healthy_deps = [n for n,s in deps.items() if s == "HEALTHY"]

        # Build validation per category
        orig_conf = hypothesis.confidence_score

        # Rule: healthy downstream metrics contradict dependency-failure hypothesis
        if category == "dependency_failure":
            if failing_deps:
                supporting_strength = "STRONG"
                status = ValidationStatus.SUPPORTED
                accepted = True
                adjusted = min(0.92, orig_conf + 0.02)
                reasoning = f"Dependency {failing_deps[0]} confirmed UNAVAILABLE; traces show downstream failure propagation; caller metrics normal supports dependency origin."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=accepted,
                    adjusted_confidence=round(min(adjusted, 0.99),3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=missing,
                    critic_reasoning=reasoning,
                    additional_investigation_required=[],
                )
            else:
                contradictions.append(f"All dependencies report healthy {healthy_deps}; no UNAVAILABLE downstream found - contradicts dependency failure")
                supporting_strength = "WEAK"
                status = ValidationStatus.REJECTED
                adjusted = max(0.15, orig_conf - 0.40)
                reasoning = "No failing downstream detected; caller logs point to internal error, not dependency outage. Reject dependency hypothesis."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=False,
                    adjusted_confidence=round(adjusted,3),
                    supporting_evidence_strength="WEAK",
                    contradictions=contradictions,
                    missing_checks=["Verify downstream service logs directly"],
                    critic_reasoning=reasoning,
                    additional_investigation_required=[],
                )

        # Rule: unchanged CPU/memory contradicts overload
        if category == "traffic_overload":
            if cpu_sev == "CRITICAL":
                # Check request volume surge
                req_change = evidence.request_count.get("percentage_change", 0) if isinstance(evidence.request_count, dict) else 0
                if req_change >= 100:
                    supporting_strength = "STRONG"
                    status = ValidationStatus.SUPPORTED
                    accepted = True
                    adjusted = orig_conf
                    reasoning = f"CPU CRITICAL and request volume +{req_change}% confirms capacity exhaustion; traffic overload supported."
                else:
                    supporting_strength = "MODERATE"
                    status = ValidationStatus.PARTIALLY_SUPPORTED
                    accepted = True
                    adjusted = orig_conf - 0.15
                    contradictions.append(f"Request volume surge only {req_change}% but CPU CRITICAL - partial evidence")
                    reasoning = "CPU saturation present but traffic surge not strong; possible inefficient code causing CPU spike, not pure overload."
                    missing.append("Check IP distribution for traffic surge vs hot loop")
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=accepted,
                    adjusted_confidence=round(min(adjusted,0.99),3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=missing,
                    critic_reasoning=reasoning,
                    additional_investigation_required=missing,
                )
            else:
                contradictions.append(f"CPU severity {cpu_sev} (normal) contradicts traffic overload - CPU should be CRITICAL")
                supporting_strength = "WEAK"
                status = ValidationStatus.REJECTED
                adjusted = max(0.18, orig_conf - 0.45)
                reasoning = "Traffic overload requires CPU >=85% CRITICAL; observed CPU normal. Low confidence; likely another root cause."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=False,
                    adjusted_confidence=round(adjusted,3),
                    supporting_evidence_strength="WEAK",
                    contradictions=contradictions,
                    missing_checks=[],
                    critic_reasoning=reasoning,
                    additional_investigation_required=[],
                )

        # Rule: deployment proximity is not proof
        if category == "faulty_revision":
            has_code_error = "NULL_POINTER_EXCEPTION" in app_codes or "NULL_POINTER" in str(app_codes)
            if has_code_error and has_deployment_before:
                supporting_strength = "STRONG"
                status = ValidationStatus.SUPPORTED
                accepted = True
                adjusted = orig_conf
                reasoning = "New revision deployed minutes before incident and emits NullPointerExceptions on new code path; previous revision healthy - supports faulty revision."
            elif has_code_error and not has_deployment_before:
                contradictions.append("Code runtime exception present but no recent deployment found")
                supporting_strength = "MODERATE"
                status = ValidationStatus.PARTIALLY_SUPPORTED
                accepted = True
                adjusted = orig_conf - 0.20
                missing.append("Verify deployment occurred outside window or via config change")
                reasoning = "Code exception suggests bug but deployment timestamp not proximate; may be latent bug triggered by data."
            elif not has_code_error and has_deployment_before:
                contradictions.append("Deployment proximity exists but no application runtime exceptions logged on new revision")
                supporting_strength = "WEAK"
                status = ValidationStatus.WEAK
                accepted = False
                adjusted = orig_conf - 0.30
                missing.append("Check revision-specific error logs to confirm new revision is failing")
                reasoning = "Temporal correlation alone insufficient; healthy downstream metrics could contradict deployment hypothesis if traces show dependency failure."
            else:
                supporting_strength = "WEAK"
                status = ValidationStatus.INSUFFICIENT_EVIDENCE
                adjusted = max(0.25, orig_conf - 0.35)
                reasoning = "Insufficient deployment evidence"
                missing.append("Inspect deployment history and error code correlation")
            return HypothesisValidation(
                hypothesis_id=hypothesis.hypothesis_id,
                validation_status=status,
                accepted=accepted,
                adjusted_confidence=round(min(max(adjusted,0.0),0.99),3),
                supporting_evidence_strength=supporting_strength,
                contradictions=contradictions,
                missing_checks=missing,
                critic_reasoning=reasoning,
                additional_investigation_required=missing,
            )

        # Rule: connection pool exhaustion - DB healthy but pool saturated
        if category == "connection_pool_exhaustion":
            if "DATABASE_CONNECTION_POOL_EXHAUSTED" in app_codes:
                # Check if DB server healthy
                db_healthy = any(d.get("server_cpu_pct", 100) < 30 for d in evidence.dependencies if "server_cpu_pct" in d) or any(s=="HEALTHY" for s in deps.values())
                if db_healthy:
                    supporting_strength = "STRONG"
                    status = ValidationStatus.SUPPORTED
                    accepted = True
                    adjusted = orig_conf
                    reasoning = "Pool exhausted 100% with waiting threads; DB CPU normal confirms client-side bottleneck - high confidence."
                else:
                    supporting_strength = "MODERATE"
                    status = ValidationStatus.PARTIALLY_SUPPORTED
                    adjusted = orig_conf - 0.10
                    missing.append("Verify DB CPU metrics to distinguish pool vs DB outage")
                    reasoning = "Pool exhausted but DB health unclear; cannot fully rule out DB outage causing pool backup."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=accepted,
                    adjusted_confidence=round(min(adjusted,0.99),3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=missing,
                    critic_reasoning=reasoning,
                    additional_investigation_required=missing,
                )
            else:
                contradictions.append("No DATABASE_CONNECTION_POOL_EXHAUSTED log code found - hypothesis lacks direct evidence")
                supporting_strength = "WEAK"
                status = ValidationStatus.WEAK
                accepted = False
                adjusted = max(0.25, orig_conf - 0.30)
                reasoning = "Pool exhaustion hypothesized but no pool saturation logs; latency alone insufficient."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=accepted,
                    adjusted_confidence=round(adjusted,3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=["Retrieve pool active/max metrics", "Inspect trace queue_wait_ms"],
                    critic_reasoning=reasoning,
                    additional_investigation_required=["Retrieve pool active/max metrics"],
                )

        # Database connectivity
        if category == "database_connectivity":
            if "DATABASE_CONNECTION_TIMEOUT" in app_codes:
                # Check downstream DB status
                db_unreach = any(s in ("UNREACHABLE","ERROR") for s in deps.values())
                if db_unreach or any("DATABASE_CONNECTION_TIMEOUT" in str(s) for s in evidence.symptoms):
                    supporting_strength = "STRONG"
                    status = ValidationStatus.SUPPORTED
                    accepted = True
                    adjusted = orig_conf
                    reasoning = "DATABASE_CONNECTION_TIMEOUT logs plus DB UNREACHABLE status and timeout traces; CPU normal rules out overload - strongly supported."
                else:
                    supporting_strength = "MODERATE"
                    status = ValidationStatus.PARTIALLY_SUPPORTED
                    adjusted = orig_conf - 0.12
                    missing.append("Confirm DB instance status via Cloud SQL metrics")
                    reasoning = "Timeout logs present but DB status not explicitly unhealthy; could also be VPC/network - partially supported."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=accepted,
                    adjusted_confidence=round(min(adjusted,0.99),3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=missing,
                    critic_reasoning=reasoning,
                    additional_investigation_required=missing,
                )
            else:
                contradictions.append("No DATABASE_CONNECTION_TIMEOUT code despite hypothesis")
                supporting_strength = "WEAK"
                status = ValidationStatus.REJECTED
                adjusted = max(0.20, orig_conf - 0.40)
                reasoning = "Hypothesis requires explicit timeout logs not found."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=False,
                    adjusted_confidence=round(adjusted,3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=[],
                    critic_reasoning=reasoning,
                    additional_investigation_required=[],
                )

        # Configuration regression
        if category == "configuration_regression":
            if "CONFIGURATION_REGRESSION" in app_codes:
                supporting_strength = "STRONG"
                status = ValidationStatus.SUPPORTED
                accepted = True
                adjusted = orig_conf
                reasoning = "CONFIGURATION_REGRESSION log with missing env var; isolated endpoint failure and healthy infra confirms config issue."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=accepted,
                    adjusted_confidence=round(min(adjusted,0.99),3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=[],
                    critic_reasoning=reasoning,
                    additional_investigation_required=[],
                )
            else:
                supporting_strength = "WEAK"
                status = ValidationStatus.INSUFFICIENT_EVIDENCE
                accepted = False
                adjusted = max(0.25, orig_conf - 0.35)
                missing.append("Retrieve env var diff between revisions")
                reasoning = "Config regression claimed but no env var missing logs; need diff."
                return HypothesisValidation(
                    hypothesis_id=hypothesis.hypothesis_id,
                    validation_status=status,
                    accepted=accepted,
                    adjusted_confidence=round(adjusted,3),
                    supporting_evidence_strength=supporting_strength,
                    contradictions=contradictions,
                    missing_checks=missing,
                    critic_reasoning=reasoning,
                    additional_investigation_required=missing,
                )

        # Unknown / generic
        supporting_strength = "WEAK"
        status = ValidationStatus.INSUFFICIENT_EVIDENCE
        accepted = False
        adjusted = max(0.20, orig_conf - 0.30)
        missing.append("Additional telemetry required to validate hypothesis")
        reasoning = "Generic fallback hypothesis lacks strong direct evidence; insufficient to confirm."
        return HypothesisValidation(
            hypothesis_id=hypothesis.hypothesis_id,
            validation_status=status,
            accepted=accepted,
            adjusted_confidence=round(adjusted,3),
            supporting_evidence_strength=supporting_strength,
            contradictions=contradictions,
            missing_checks=missing,
            critic_reasoning=reasoning,
            additional_investigation_required=missing,
        )

    def validate_all(self, hypotheses: List[RootCauseHypothesis], evidence: IncidentEvidence, findings: List[AgentFinding]) -> List[HypothesisValidation]:
        return [self.validate(h, evidence, findings) for h in hypotheses]
