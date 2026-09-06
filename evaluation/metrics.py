"""
Evaluation Metrics for Cloud Incident RCA Agent.
Computes:
  - RCA accuracy (% of incidents where predicted root cause matches ground truth)
  - Evidence precision (% of cited evidence items that align with actual telemetry)
  - Confidence calibration (mean confidence on correct predictions vs incorrect)
  - Unsupported-claim rate (% of claims made without cited evidence)
"""
from typing import List, Dict, Any


def calculate_rca_accuracy(results: List[Dict[str, Any]]) -> float:
    """Computes fraction of correctly categorized root causes."""
    if not results:
        return 0.0
    correct = sum(1 for r in results if r.get("category_matched", False))
    return round(correct / len(results), 4)


def calculate_evidence_precision(results: List[Dict[str, Any]]) -> float:
    """Computes fraction of cited evidence items deemed valid and relevant."""
    total_cited = 0
    total_valid = 0
    for r in results:
        cited = r.get("cited_evidence_count", 0)
        valid = r.get("valid_evidence_count", 0)
        total_cited += cited
        total_valid += valid
    if total_cited == 0:
        return 0.0
    return round(total_valid / total_cited, 4)


def calculate_confidence_calibration(results: List[Dict[str, Any]]) -> float:
    """Computes average confidence score for correct predictions."""
    correct_confidences = [r["confidence_score"] for r in results if r.get("category_matched", False)]
    if not correct_confidences:
        return 0.0
    return round(sum(correct_confidences) / len(correct_confidences), 4)


def calculate_unsupported_claim_rate(results: List[Dict[str, Any]]) -> float:
    """Computes fraction of incidents where a definitive root cause was claimed with 0 cited evidence."""
    if not results:
        return 0.0
    unsupported = sum(1 for r in results if r.get("is_unsupported", False))
    return round(unsupported / len(results), 4)
