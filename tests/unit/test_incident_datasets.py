"""
Unit test verifying that all 6 synthetic incidents and expected RCAs
conform strictly to schemas IncidentEvidence and RCAResult.
"""
import glob
import json
import os
from schemas.evidence import IncidentEvidence
from schemas.rca import RCAResult

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")


SCENARIOS = [
    ("incident_001_db_timeout.json", "rca_001_db_timeout.json"),
    ("incident_002_pool_exhaustion.json", "rca_002_pool_exhaustion.json"),
    ("incident_003_bad_deployment.json", "rca_003_bad_deployment.json"),
    ("incident_004_dependency_outage.json", "rca_004_dependency_outage.json"),
    ("incident_005_traffic_overload.json", "rca_005_traffic_overload.json"),
    ("incident_006_config_regression.json", "rca_006_config_regression.json"),
]


def test_all_six_synthetic_incidents_conform_to_schema():
    incidents_dir = os.path.join(DATA_DIR, "incidents")
    for inc_file, _ in SCENARIOS:
        fpath = os.path.join(incidents_dir, inc_file)
        assert os.path.exists(fpath), f"Incident file missing: {inc_file}"
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        evidence = IncidentEvidence(**data)
        assert evidence.incident_id.startswith("INC-")
        assert evidence.severity in ["P1", "P2", "P3"]
        assert len(evidence.symptoms) > 0


def test_all_six_expected_rcas_conform_to_schema():
    rcas_dir = os.path.join(DATA_DIR, "expected_rcas")
    categories = set()
    for _, rca_file in SCENARIOS:
        fpath = os.path.join(rcas_dir, rca_file)
        assert os.path.exists(fpath), f"Expected RCA file missing: {rca_file}"
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        rca = RCAResult(**data)
        assert rca.incident_id.startswith("INC-")
        assert 0.0 <= rca.confidence_score <= 1.0
        assert rca.remediation_risk in ["LOW", "MEDIUM", "HIGH"]
        assert len(rca.evidence) > 0
        categories.add(rca.root_cause_category)

    # Check that distinct ground-truth categories exist
    expected_categories = {
        "database_connectivity",
        "connection_pool_exhaustion",
        "faulty_revision",
        "dependency_failure",
        "traffic_overload",
        "configuration_regression"
    }
    assert expected_categories.issubset(categories), f"Missing categories: {expected_categories - categories}"
