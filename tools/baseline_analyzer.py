"""
Baseline vs Incident Comparison Utility.
Compares baseline period metrics with incident period metrics and calculates
percentage change and an objective severity indicator (NORMAL, WARNING, CRITICAL).
"""
from typing import Dict, Any, Union


def _calculate_pct_change(baseline: float, incident: float) -> float:
    """Calculates percentage change safely."""
    if baseline == 0.0:
        return 100.0 if incident > 0 else 0.0
    return round(((incident - baseline) / baseline) * 100.0, 2)


def compare_error_rate(baseline_val: float, incident_val: float) -> Dict[str, Any]:
    """
    Compares HTTP error rate (percent 5xx or failed requests).
    Severity thresholds:
      - CRITICAL: incident >= 10.0% or delta >= +10.0%
      - WARNING: incident >= 2.0% or delta >= +2.0%
      - NORMAL: otherwise
    """
    pct_change = _calculate_pct_change(baseline_val, incident_val)
    if incident_val >= 10.0 or (incident_val - baseline_val) >= 10.0:
        severity = "CRITICAL"
    elif incident_val >= 2.0 or (incident_val - baseline_val) >= 2.0:
        severity = "WARNING"
    else:
        severity = "NORMAL"

    return {
        "baseline": round(baseline_val, 2),
        "incident": round(incident_val, 2),
        "percentage_change": pct_change,
        "severity": severity
    }


def compare_latency(baseline_val: float, incident_val: float) -> Dict[str, Any]:
    """
    Compares request latency (typically p95 or p99 in milliseconds).
    Severity thresholds:
      - CRITICAL: latency >= 3000ms or (> 300% increase and latency >= 2000ms)
      - WARNING: latency >= 1000ms or (> 50% increase and latency >= 400ms)
      - NORMAL: otherwise
    """
    pct_change = _calculate_pct_change(baseline_val, incident_val)
    if incident_val >= 3000.0 or (pct_change >= 300.0 and incident_val >= 2000.0):
        severity = "CRITICAL"
    elif incident_val >= 1000.0 or (pct_change >= 50.0 and incident_val >= 400.0):
        severity = "WARNING"
    else:
        severity = "NORMAL"

    return {
        "baseline": round(baseline_val, 2),
        "incident": round(incident_val, 2),
        "percentage_change": pct_change,
        "severity": severity
    }


def compare_request_volume(baseline_val: float, incident_val: float) -> Dict[str, Any]:
    """
    Compares incoming request count / volume per second or per minute.
    Severity thresholds:
      - CRITICAL: > 200% spike (traffic surge) or > 80% drop (ingress/upstream breakage)
      - WARNING: > 50% spike or > 30% drop
      - NORMAL: within normal fluctuations
    """
    pct_change = _calculate_pct_change(baseline_val, incident_val)
    if pct_change >= 200.0 or pct_change <= -80.0:
        severity = "CRITICAL"
    elif pct_change >= 50.0 or pct_change <= -30.0:
        severity = "WARNING"
    else:
        severity = "NORMAL"

    return {
        "baseline": round(baseline_val, 2),
        "incident": round(incident_val, 2),
        "percentage_change": pct_change,
        "severity": severity
    }


def compare_cpu(baseline_val: float, incident_val: float) -> Dict[str, Any]:
    """
    Compares CPU utilization (percentage 0.0 to 100.0%).
    Severity thresholds:
      - CRITICAL: incident >= 85.0%
      - WARNING: incident >= 70.0% or spike > +30%
      - NORMAL: otherwise
    """
    pct_change = _calculate_pct_change(baseline_val, incident_val)
    if incident_val >= 85.0:
        severity = "CRITICAL"
    elif incident_val >= 70.0 or (incident_val - baseline_val >= 30.0):
        severity = "WARNING"
    else:
        severity = "NORMAL"

    return {
        "baseline": round(baseline_val, 2),
        "incident": round(incident_val, 2),
        "percentage_change": pct_change,
        "severity": severity
    }


def compare_memory(baseline_val: float, incident_val: float) -> Dict[str, Any]:
    """
    Compares Memory utilization (percentage 0.0 to 100.0%).
    Severity thresholds:
      - CRITICAL: incident >= 90.0% (high risk of OOM kills)
      - WARNING: incident >= 75.0% or delta > +25%
      - NORMAL: otherwise
    """
    pct_change = _calculate_pct_change(baseline_val, incident_val)
    if incident_val >= 90.0:
        severity = "CRITICAL"
    elif incident_val >= 75.0 or (incident_val - baseline_val >= 25.0):
        severity = "WARNING"
    else:
        severity = "NORMAL"

    return {
        "baseline": round(baseline_val, 2),
        "incident": round(incident_val, 2),
        "percentage_change": pct_change,
        "severity": severity
    }
