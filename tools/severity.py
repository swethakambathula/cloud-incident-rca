"""
Incident Severity Classifier.
Deterministically classifies incident severity into P1, P2, or P3 based on
observable telemetry metrics, error rates, and blast radius.
"""
from typing import Dict, Any, List


def classify_incident_severity(
    error_rate_pct: float,
    latency_p95_ms: float,
    affected_endpoints: List[str],
    is_service_down: bool = False,
    is_downstream_broken: bool = False
) -> str:
    """
    Classifies incident severity based on observable telemetry evidence:
      - P1 (Critical): Major customer-facing outage, complete service unreachability,
                       error rate >= 15%, or multiple critical endpoints failing.
      - P2 (Major): Significant degradation, error rate between 5% and 15%,
                    or p95 latency > 3000ms.
      - P3 (Minor): Limited or localized impact, error rate < 5%, single isolated endpoint.
    """
    if is_service_down or error_rate_pct >= 15.0 or (len(affected_endpoints) >= 3 and error_rate_pct >= 8.0):
        return "P1"

    if error_rate_pct >= 5.0 or latency_p95_ms >= 3000.0 or (is_downstream_broken and error_rate_pct >= 3.0):
        return "P2"

    return "P3"
