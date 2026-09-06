"""
RCA Evaluator.
Executes the RCA Agent against ground truth incidents and compares results
against expected golden RCAs.
"""
import os
import json
from typing import List, Dict, Any
from agents.rca_agent.agent import CloudRCAAgent
from schemas.evidence import IncidentEvidence
from schemas.rca import RCAResult
from .metrics import (
    calculate_rca_accuracy,
    calculate_evidence_precision,
    calculate_confidence_calibration,
    calculate_unsupported_claim_rate,
)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")

GROUND_TRUTH_PAIRS = [
    ("incident_001_db_timeout.json", "rca_001_db_timeout.json"),
    ("incident_002_pool_exhaustion.json", "rca_002_pool_exhaustion.json"),
    ("incident_003_bad_deployment.json", "rca_003_bad_deployment.json"),
    ("incident_004_dependency_outage.json", "rca_004_dependency_outage.json"),
    ("incident_005_traffic_overload.json", "rca_005_traffic_overload.json"),
    ("incident_006_config_regression.json", "rca_006_config_regression.json"),
]


class RCAEvaluator:
    """Evaluates RCA Agent accuracy and evidence quality against golden incidents."""

    def __init__(self, agent: CloudRCAAgent = None):
        self.agent = agent or CloudRCAAgent()

    def run_evaluation(self) -> Dict[str, Any]:
        """Runs evaluation across all golden incidents."""
        incident_evaluations: List[Dict[str, Any]] = []

        for inc_filename, rca_filename in GROUND_TRUTH_PAIRS:
            inc_path = os.path.join(DATA_DIR, "incidents", inc_filename)
            rca_path = os.path.join(DATA_DIR, "expected_rcas", rca_filename)

            with open(inc_path, "r", encoding="utf-8") as f:
                inc_data = json.load(f)
            with open(rca_path, "r", encoding="utf-8") as f:
                expected_data = json.load(f)

            evidence = IncidentEvidence(**inc_data)
            expected_rca = RCAResult(**expected_data)

            predicted_rca = self.agent.analyze(evidence)

            # Check matching category
            category_matched = (predicted_rca.root_cause_category == expected_rca.root_cause_category)

            # Evidence checks
            cited_count = len(predicted_rca.evidence)
            # Evidence is considered valid if it cites non-empty telemetry facts
            valid_evidence_count = sum(1 for e in predicted_rca.evidence if len(e.strip()) > 10)
            contradictory_considered = len(predicted_rca.contradictory_evidence) > 0

            # Unsupported claim: claimed definitive category with 0 evidence
            is_unsupported = (predicted_rca.root_cause_category != "unknown" and cited_count == 0)

            incident_evaluations.append({
                "incident_id": evidence.incident_id,
                "file": inc_filename,
                "expected_category": expected_rca.root_cause_category,
                "predicted_category": predicted_rca.root_cause_category,
                "category_matched": category_matched,
                "confidence_score": predicted_rca.confidence_score,
                "cited_evidence_count": cited_count,
                "valid_evidence_count": valid_evidence_count,
                "contradictory_considered": contradictory_considered,
                "is_unsupported": is_unsupported,
                "remediation_risk": predicted_rca.remediation_risk
            })

        summary = {
            "total_incidents": len(incident_evaluations),
            "rca_accuracy": calculate_rca_accuracy(incident_evaluations),
            "evidence_precision": calculate_evidence_precision(incident_evaluations),
            "confidence_calibration": calculate_confidence_calibration(incident_evaluations),
            "unsupported_claim_rate": calculate_unsupported_claim_rate(incident_evaluations),
            "results": incident_evaluations
        }
        return summary
