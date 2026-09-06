"""
Unit tests for severity classification and blast radius detection.
"""
from tools.severity import classify_incident_severity
from tools.blast_radius import detect_blast_radius


def test_classify_incident_severity():
    # P1 cases: high error rate or service down
    assert classify_incident_severity(18.0, 500.0, ["/simulate/error"]) == "P1"
    assert classify_incident_severity(2.0, 500.0, ["/a", "/b", "/c"], is_service_down=True) == "P1"

    # P2 cases: moderate error rate or high latency
    assert classify_incident_severity(8.0, 500.0, ["/simulate/error"]) == "P2"
    assert classify_incident_severity(1.0, 3500.0, ["/simulate/latency"]) == "P2"

    # P3 cases: minor localized error
    assert classify_incident_severity(2.0, 300.0, ["/simulate/config-error"]) == "P3"


def test_detect_blast_radius():
    res = detect_blast_radius(
        service_name="demo-service",
        revision_name="demo-service-00003-abc",
        region="us-central1",
        affected_endpoints=["/simulate/error"],
        dependencies_affected=[]
    )
    assert res["scope"] == "endpoint-isolated"
    assert res["affected_services"] == ["demo-service"]
    assert "us-central1" in res["regional_scope"]

    # Multi-service cascade
    cascade_res = detect_blast_radius(
        service_name="checkout-service",
        revision_name="checkout-00001",
        region="us-central1",
        affected_endpoints=["/checkout"],
        dependencies_affected=["orders-service"]
    )
    assert cascade_res["scope"] == "multi-service-cascade"
    assert "orders-service" in cascade_res["affected_services"]
