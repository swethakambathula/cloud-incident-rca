"""
Verification Agent - deterministic rules decide recovery, Gemini summarizes only.
"""
from typing import Dict, Any
from .schemas import VerificationResult, VerificationStatus
from agents.executor_agent.schemas import ExecutionResult

class VerificationAgent:
    agent_name = "Verification Agent"

    def verify(self, incident_id: str, execution: ExecutionResult, metrics_before: Dict[str, Any], metrics_after: Dict[str, Any]) -> VerificationResult:
        # Extract error rates and latency
        err_before = metrics_before.get("error_rate_pct", metrics_before.get("error_rate", 0.0))
        err_after = metrics_after.get("error_rate_pct", metrics_after.get("error_rate", 0.0))
        lat_before = metrics_before.get("latency_p95_ms", metrics_before.get("latency", 0.0))
        lat_after = metrics_after.get("latency_p95_ms", metrics_after.get("latency", 0.0))
        # Also handle evidence latency dict shapes
        if isinstance(err_before, dict):
            err_before = err_before.get("incident", 0.0)
        if isinstance(err_after, dict):
            err_after = err_after.get("incident", 0.0)

        # Deterministic thresholds
        # Resolved: error returns near baseline (e.g., <2%) and latency within acceptable (<500ms or <1.5x baseline)
        baseline_err = metrics_before.get("baseline_error_rate", 0.5)
        baseline_lat = metrics_before.get("baseline_latency", 150)

        # Heuristics:
        # error_after <2% and lat_after <500 or drop >50% from before
        resolved = False
        regressed = False
        partial = False

        # Detect regression: error increased
        if err_after > err_before + 5:
            regressed = True
            status = VerificationStatus.REGRESSED
        elif err_after < 2.0 and lat_after < 500:
            resolved = True
            status = VerificationStatus.RESOLVED
        elif err_after < err_before * 0.5:  # at least 50% drop
            partial = True
            status = VerificationStatus.PARTIALLY_RESOLVED
        else:
            status = VerificationStatus.NOT_RESOLVED

        # Check insufficient data
        if not metrics_after or err_after == 0 and lat_after == 0 and len(metrics_after)==0:
            status = VerificationStatus.INSUFFICIENT_DATA

        new_issues = False
        # Simple: if latency still high but error low, maybe new issues? Not flagged

        return VerificationResult(
            incident_id=incident_id,
            execution_id=execution.execution_id if execution else "no-exec",
            verification_status=status,
            metrics_before=metrics_before,
            metrics_after=metrics_after,
            error_rate_before=float(err_before) if isinstance(err_before,(int,float)) else 0.0,
            error_rate_after=float(err_after) if isinstance(err_after,(int,float)) else 0.0,
            latency_before=float(lat_before) if isinstance(lat_before,(int,float)) else 0.0,
            latency_after=float(lat_after) if isinstance(lat_after,(int,float)) else 0.0,
            service_health_before="DEGRADED" if err_before>2 else "HEALTHY",
            service_health_after="HEALTHY" if status==VerificationStatus.RESOLVED else "DEGRADED",
            customer_impact_before="HIGH" if err_before>5 else "LOW",
            customer_impact_after="NONE" if status==VerificationStatus.RESOLVED else "HIGH" if err_after>5 else "MEDIUM",
            resolved=resolved,
            partial_recovery=partial,
            new_issues_detected=new_issues,
            verification_confidence=0.92 if status in (VerificationStatus.RESOLVED, VerificationStatus.REGRESSED) else 0.75,
            summary=f"Error {err_before}% -> {err_after}%, latency {lat_before}ms -> {lat_after}ms => {status.value}"
        )

    def verification_window(self, max_window_minutes: int = 5) -> Dict[str, int]:
        return {"initial_check_seconds": 60, "follow_up_seconds": 180, "max_window_minutes": max_window_minutes}
