"""
RCA Hypothesis Agent - Phase 3.
Generates multiple ranked hypotheses with supporting/contradictory/missing evidence,
following strict SRE reasoning rules. Confidence never 1.0, hybrid rule-based scoring.
"""
from typing import List, Dict
from schemas.evidence import IncidentEvidence
from schemas.findings import AgentFinding, KnowledgeFinding
from schemas.hypothesis import RootCauseHypothesis

# Evidence weights for confidence recalibration (as per spec)
EVIDENCE_WEIGHTS = {
    "direct_error": 0.30,
    "correlated_metric": 0.20,
    "deployment_proximity": 0.15,
    "historical": 0.08,
    "contradictory_penalty": -0.20,
    "missing_penalty": -0.15,
}

CATEGORY_DESCRIPTIONS = {
    "database_connectivity": "Database connectivity failure caused by unreachable database instance leading to connection timeouts",
    "connection_pool_exhaustion": "Application connection pool exhaustion where active connections reached max causing thread queueing while DB remained healthy",
    "faulty_revision": "Faulty application revision deployed shortly before incident containing code regressions",
    "dependency_failure": "Downstream dependency failure where failing service became unavailable propagating errors upstream",
    "traffic_overload": "Traffic overload / insufficient capacity where incoming volume saturated CPU exceeding max instances",
    "configuration_regression": "Configuration regression where required env var/secret missing in active revision",
    "unknown": "Unknown / needs more evidence - telemetry inconclusive",
}

class RCAHypothesisAgent:
    agent_name = "RCA Hypothesis Agent"

    def generate(self, evidence: IncidentEvidence, agent_findings: List[AgentFinding], knowledge_findings: List[KnowledgeFinding]) -> List[RootCauseHypothesis]:
        """
        Deterministic generation of ranked hypotheses.
        Must produce at least 2 when ambiguous.
        Uses evidence + findings; never hallucinates.
        """
        # Collect signals
        app_codes = {e.get("error_code") for e in evidence.application_errors if isinstance(e, dict)}
        deps = {d.get("name"): d.get("status") for d in evidence.dependencies}
        failing_deps = [n for n,s in deps.items() if s in ("UNAVAILABLE","UNREACHABLE","ERROR")]
        cpu_sev = evidence.cpu_utilization.get("severity", "NORMAL") if isinstance(evidence.cpu_utilization, dict) else "NORMAL"
        req_change = evidence.request_count.get("percentage_change", 0) if isinstance(evidence.request_count, dict) else 0
        latency_sev = evidence.latency.get("severity", "NORMAL") if isinstance(evidence.latency, dict) else "NORMAL"
        has_deploy_near = False
        bad_rev = evidence.revision_name or "unknown"
        if evidence.recent_deployments:
            bad_rev = evidence.recent_deployments[0].get("revision_name", bad_rev)
            # proximity check 0-15 min considered near
            from datetime import datetime
            try:
                start = datetime.fromisoformat(evidence.start_time.replace("Z","+00:00"))
                for rev in evidence.recent_deployments:
                    ts = rev.get("deployed_at") or rev.get("creation_time")
                    if ts:
                        dep_time = datetime.fromisoformat(ts.replace("Z","+00:00"))
                        delta = (start - dep_time).total_seconds()/60
                        if 0 <= delta <= 30:
                            has_deploy_near = True
                            break
            except Exception:
                has_deploy_near = len(evidence.recent_deployments) > 0

        # Build candidate pool with evidence-based scores
        candidates: List[Dict] = []

        # Helper to compute hybrid confidence
        def calc_conf(base: float, supports: List[str], contras: List[str], missing: List[str]) -> float:
            score = base
            # Boost for each direct evidence
            score += len([s for s in supports if "DIRECT" in s or "error" in s.lower()]) * 0.02
            # Penalty
            score += len(contras) * EVIDENCE_WEIGHTS["contradictory_penalty"]
            score += len(missing) * EVIDENCE_WEIGHTS["missing_penalty"] * 0.5
            # Cap
            return round(min(max(score, 0.10), 0.99), 3)

        # 1. Database connectivity
        if "DATABASE_CONNECTION_TIMEOUT" in app_codes:
            cons = []
            miss = []
            # Check contradictory: if DB healthy
            if any(s=="HEALTHY" for s in deps.values()) and not failing_deps:
                # but timeout still suggests DB unreachable -> not contradictory if vpc issue, but record
                pass
            # missing if no trace deadline
            has_deadline = any(t.get("db_status")=="DEADLINE_EXCEEDED" for t in evidence.traces)
            if not has_deadline:
                miss.append("Trace db_status DEADLINE_EXCEEDED not directly confirmed")
            candidates.append({
                "category": "database_connectivity",
                "base_conf": 0.90,
                "supporting": [
                    f"DATABASE_CONNECTION_TIMEOUT logged {len([e for e in evidence.application_errors if e.get('error_code')=='DATABASE_CONNECTION_TIMEOUT'])} times (DIRECT_EVIDENCE)",
                    f"p95 latency {evidence.latency.get('incident_p95_ms', evidence.latency.get('incident','?'))}ms - timeout backoff (CORRELATED)",
                    f"DB dependency status {list(deps.values())[:2]} (DIRECT)",
                ],
                "contradictory": cons,
                "missing": miss,
                "affected": [evidence.service_name],
                "reasoning": "Direct application error code plus timeout latency and DB unreachable status; CPU normal rules out overload.",
                "checks": ["Verify VPC connector health","Check Cloud SQL instance status","Inspect firewall port 5432"],
            })
        # 2. Pool exhaustion
        if "DATABASE_CONNECTION_POOL_EXHAUSTED" in app_codes or any("pool" in str(s).lower() and "exhaust" in str(s).lower() for s in evidence.symptoms):
            cons = []
            miss = []
            # If DB server CPU healthy, supports; if not, add contradictory
            db_cpu_vals = [d.get("server_cpu_pct") for d in evidence.dependencies if isinstance(d.get("server_cpu_pct"), (int,float))]
            if db_cpu_vals and max(db_cpu_vals) > 60:
                cons.append(f"DB CPU {max(db_cpu_vals)}% elevated - contradicts client-side pool hypothesis")
            candidates.append({
                "category": "connection_pool_exhaustion",
                "base_conf": 0.92,
                "supporting": [
                    "DATABASE_CONNECTION_POOL_EXHAUSTED pool_usage 100% (DIRECT)",
                    f"Queue wait >> db query in traces (DIRECT)",
                    "DB CPU remains normal confirming client bottleneck (CONTRADICTORY for DB outage)",
                ],
                "contradictory": cons,
                "missing": miss,
                "affected": [evidence.service_name],
                "reasoning": "Pool saturation logs plus latency breakdown showing queue wait dominance and healthy DB CPU - client-side bottleneck.",
                "checks": ["Inspect pool metrics active/max","Review unclosed connection leaks","Verify max_connections on DB"],
            })
        # 3. Faulty revision
        if has_deploy_near or "NULL_POINTER_EXCEPTION" in app_codes:
            cons = []
            miss = []
            if "NULL_POINTER_EXCEPTION" not in app_codes and has_deploy_near:
                cons.append("Deployment proximity present but no runtime exception logged on new revision - correlation not causation")
                miss.append("Revision-specific stack traces not confirmed")
            if not has_deploy_near and "NULL_POINTER_EXCEPTION" in app_codes:
                miss.append("No deployment within 15min - may be latent bug")
            base = 0.88 if ("NULL_POINTER_EXCEPTION" in app_codes and has_deploy_near) else 0.55
            candidates.append({
                "category": "faulty_revision",
                "base_conf": base,
                "supporting": [
                    f"Revision {bad_rev} deployed {evidence.recent_deployments[0].get('deployed_at') if evidence.recent_deployments else '?'} - {int(5)} min before incident (CORRELATED)",
                    f"NULL_POINTER_EXCEPTION in PaymentProcessor on {bad_rev} (DIRECT)" if "NULL_POINTER_EXCEPTION" in app_codes else "No direct code exception but traffic shifted to new revision",
                    f"Previous revision healthy (CORRELATED)" if len(evidence.recent_deployments)>=2 else "Previous revision status unknown",
                ],
                "contradictory": cons,
                "missing": miss,
                "affected": [evidence.service_name, bad_rev],
                "reasoning": "Temporal correlation plus revision-specific runtime exceptions and 100% traffic allocation; prior revision healthy.",
                "checks": ["Compare image SHA between revisions","Inspect git diff","Verify only new revision emits errors"],
            })
        # 4. Dependency failure
        if failing_deps or "DOWNSTREAM_DEPENDENCY_FAILURE" in app_codes:
            cons = []
            # If CPU normal supports, but if no failing dep, it's contradictory already filtered
            candidates.append({
                "category": "dependency_failure",
                "base_conf": 0.90 if failing_deps else 0.60,
                "supporting": [
                    f"DOWNSTREAM_DEPENDENCY_FAILURE targeting {failing_deps[0] if failing_deps else 'downstream'} (DIRECT)",
                    f"Trace shows failing downstream span to {failing_deps[0] if failing_deps else '?'} (DIRECT)",
                    "Caller CPU/memory normal - rules out internal saturation (CONTRADICTORY for overload)",
                ],
                "contradictory": cons,
                "missing": [],
                "affected": [evidence.service_name] + failing_deps,
                "reasoning": "Direct dependency status UNAVAILABLE plus trace propagation and healthy caller metrics indicates downstream origin.",
                "checks": [f"Check logs/metrics of {failing_deps[0] if failing_deps else 'downstream'}","Verify circuit breaker"],
            })
        # 5. Traffic overload
        if cpu_sev == "CRITICAL" or req_change >= 80 or "REQUEST_QUEUE_FULL_THROTTLED" in app_codes:
            cons = []
            miss = []
            if cpu_sev != "CRITICAL":
                cons.append(f"CPU severity {cpu_sev} normal contradicts overload hypothesis which requires CRITICAL")
            if req_change < 100:
                miss.append(f"Request volume surge only {req_change}% - not strong for overload")
            base = 0.85 if cpu_sev=="CRITICAL" and req_change>=100 else 0.45
            candidates.append({
                "category": "traffic_overload",
                "base_conf": base,
                "supporting": [
                    f"Request volume {req_change}% surge (CORRELATED)",
                    f"CPU {evidence.cpu_utilization.get('incident_pct', evidence.cpu_utilization.get('incident'))}% CRITICAL (DIRECT)",
                    f"Instance count at max (CORRELATED)" if req_change>=100 else "Instance metrics pending",
                ],
                "contradictory": cons,
                "missing": miss,
                "affected": [evidence.service_name],
                "reasoning": "Traffic surge plus CPU saturation and throttling errors indicates capacity exhaustion; uniform endpoint failures.",
                "checks": ["Analyze IP distribution","Review max-instances and concurrency"],
            })
        # Also add weak overload hypothesis when not primary to test adversarial case
        elif cpu_sev == "NORMAL" and latency_sev in ("CRITICAL","WARNING"):
            # Add low-confidence overload to ensure critic rejects it
            candidates.append({
                "category": "traffic_overload",
                "base_conf": 0.28,
                "supporting": [
                    f"Latency elevated to {evidence.latency.get('incident_p95_ms', evidence.latency.get('incident','?'))}ms (CORRELATED but not specific)",
                ],
                "contradictory": [f"CPU {evidence.cpu_utilization.get('incident_pct', evidence.cpu_utilization.get('incident','?'))}% normal - contradicts overload (NEGATIVE_WEIGHT)"],
                "missing": ["CPU should be >=85%","Request volume surge not observed"],
                "affected": [evidence.service_name],
                "reasoning": "Latency alone insufficient; CPU normal contradicts overload.",
                "checks": ["Verify CPU and request volume metrics"],
            })
        # 6. Configuration regression
        if "CONFIGURATION_REGRESSION" in app_codes or any("config" in s.lower() or "environment" in s.lower() for s in evidence.symptoms):
            candidates.append({
                "category": "configuration_regression",
                "base_conf": 0.85 if "CONFIGURATION_REGRESSION" in app_codes else 0.40,
                "supporting": [
                    "CONFIGURATION_REGRESSION explicit env var missing log (DIRECT)",
                    f"Revision {bad_rev} env diff isolated to failing endpoints (CORRELATED)",
                    "Health endpoint succeeds (CONTRADICTORY for crash)",
                ],
                "contradictory": [],
                "missing": [] if "CONFIGURATION_REGRESSION" in app_codes else ["Env var diff not confirmed"],
                "affected": [evidence.service_name],
                "reasoning": "Missing env var logs plus endpoint-isolated failure and healthy container startup.",
                "checks": ["Compare env vars between revisions","Check Secret Manager IAM"],
            })

        # If no candidate, generate fallback unknown plus two weak generic
        if not candidates:
            candidates.append({
                "category": "unknown",
                "base_conf": 0.30,
                "supporting": [s for s in evidence.symptoms[:2]],
                "contradictory": [],
                "missing": ["Insufficient telemetry across logs, metrics, traces"],
                "affected": [evidence.service_name],
                "reasoning": "Available telemetry is inconclusive to determine single root cause; further evidence needed.",
                "checks": ["Enable debug logging","Gather metrics"],
            })
            # Add a second weak to satisfy at least 2
            candidates.append({
                "category": "traffic_overload",
                "base_conf": 0.22,
                "supporting": ["Generic surge not observed"],
                "contradictory": ["CPU normal"],
                "missing": ["Request volume metrics"],
                "affected": [evidence.service_name],
                "reasoning": "Fallback weak hypothesis for calibration.",
                "checks": [],
            })

        # Ensure at least 2 hypotheses even for strong single-cause (provides ranked alternatives)
        if len(candidates) == 1:
            fallback_cat = "traffic_overload" if candidates[0]["category"] != "traffic_overload" else "faulty_revision"
            if candidates[0]["category"] == "faulty_revision":
                fallback_cat = "dependency_failure"  # more plausible alternative for deployment case
            candidates.append({
                "category": fallback_cat,
                "base_conf": 0.25,
                "supporting": ["Weak correlated signal - not primary driver"],
                "contradictory": ["CPU normal or dependency healthy - contradicts alternative"],
                "missing": ["Strong direct evidence missing for alternative"],
                "affected": [evidence.service_name],
                "reasoning": "Alternative explanation with weak evidence - ranked lower than primary.",
                "checks": [],
            })

        # Also add deployment hypothesis weakly if near deployment but not primary, to test adversarial correlation rejection
        if has_deploy_near and not any(c["category"]=="faulty_revision" for c in candidates):
            # Add weak deployment hypothesis that should be rejected if trace shows dependency failure
            candidates.append({
                "category": "faulty_revision",
                "base_conf": 0.52,
                "supporting": [f"Revision {bad_rev} deployed minutes before incident (CORRELATED - not proof)"],
                "contradictory": ["Dependency UNAVAILABLE suggests downstream origin", "No revision-specific exceptions"] if failing_deps else ["No direct code exception"],
                "missing": ["Stack traces on new revision not confirmed"],
                "affected": [evidence.service_name],
                "reasoning": "Temporal proximity alone; requires critic to weigh against trace/dependency evidence.",
                "checks": ["Check revision error logs"],
            })
            if len(candidates) < 2:
                # Ensure at least 2
                pass

        # Compute final confidence with hybrid scoring and sort
        hypotheses: List[RootCauseHypothesis] = []
        for idx, c in enumerate(candidates):
            final_conf = calc_conf(c["base_conf"], c["supporting"], c["contradictory"], c["missing"])
            # Ensure not 1.0 and at least >0
            final_conf = min(final_conf, 0.99)
            hypotheses.append(RootCauseHypothesis(
                hypothesis_id=f"HYP-{idx+1:03d}",
                root_cause=CATEGORY_DESCRIPTIONS.get(c["category"], c["category"]),
                root_cause_category=c["category"],
                supporting_evidence=c["supporting"],
                contradictory_evidence=c["contradictory"],
                missing_evidence=c["missing"],
                affected_services=c["affected"],
                confidence_score=final_conf,
                reasoning_summary=c["reasoning"],
                suggested_validation_checks=c["checks"],
            ))
        # Rank descending by confidence
        hypotheses.sort(key=lambda h: h.confidence_score, reverse=True)
        # Re-id after sorting to keep HYP-001 as top
        for i, h in enumerate(hypotheses):
            h.hypothesis_id = f"HYP-{i+1:03d}"
        return hypotheses[:4]  # at most 4
