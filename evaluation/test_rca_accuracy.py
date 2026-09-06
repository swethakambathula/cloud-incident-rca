"""
Automated Pytest for Phase 1 Ground-Truth RCA Accuracy.
"""
import pytest
from evaluation.evaluator import RCAEvaluator


def test_phase_1_rca_accuracy_and_metrics():
    evaluator = RCAEvaluator()
    summary = evaluator.run_evaluation()

    assert summary["total_incidents"] == 6, "Must evaluate all 6 ground-truth incidents"
    assert summary["rca_accuracy"] == 1.0, f"RCA Accuracy was {summary['rca_accuracy']}, expected 1.0 (100%)"
    assert summary["evidence_precision"] >= 0.90, f"Evidence precision {summary['evidence_precision']} was below 0.90"
    assert 0.85 <= summary["confidence_calibration"] <= 1.0, "Confidence calibration out of bounds"
    assert summary["unsupported_claim_rate"] == 0.0, "Found unsupported claims in RCA"

    for r in summary["results"]:
        assert r["category_matched"] is True, f"Failed on {r['incident_id']}"
        assert r["contradictory_considered"] is True, f"Contradictory evidence not considered for {r['incident_id']}"
        assert r["cited_evidence_count"] > 0, f"No evidence cited for {r['incident_id']}"
