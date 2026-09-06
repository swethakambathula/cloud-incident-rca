"""
Unit tests for demo_service endpoints and structured logging.
"""
from fastapi.testclient import TestClient
from demo_service.main import app as checkout_app
from demo_service.orders_service import app as orders_app

checkout_client = TestClient(checkout_app, raise_server_exceptions=False)
orders_client = TestClient(orders_app, raise_server_exceptions=False)


def test_checkout_health():
    res = checkout_client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_checkout_simulate_error():
    res = checkout_client.get("/simulate/error")
    assert res.status_code == 500
    assert "DATABASE_CONNECTION_TIMEOUT" in res.json()["detail"]


def test_checkout_simulate_pool_exhaustion():
    res = checkout_client.get("/simulate/pool-exhaustion")
    assert res.status_code == 500
    assert "DATABASE_CONNECTION_POOL_EXHAUSTED" in res.json()["detail"]


def test_checkout_simulate_config_error():
    res = checkout_client.get("/simulate/config-error")
    assert res.status_code == 500
    assert "CONFIGURATION_REGRESSION" in res.json()["detail"]


def test_checkout_simulate_latency():
    res = checkout_client.get("/simulate/latency?duration_seconds=0.01")
    assert res.status_code == 200
    assert res.json()["status"] == "degraded"


def test_checkout_simulate_cpu():
    res = checkout_client.get("/simulate/cpu?intensity=1000")
    assert res.status_code == 200
    assert res.json()["status"] == "completed"


def test_orders_service_flow():
    # Normal
    res = orders_client.get("/orders")
    assert res.status_code == 200
    assert len(res.json()["orders"]) >= 1

    # Toggle failure
    res_toggle = orders_client.post("/fail/enable")
    assert res_toggle.json()["failure_mode"] is True

    # Failed call
    res_fail = orders_client.get("/orders")
    assert res_fail.status_code == 503

    # Reset
    orders_client.post("/fail/disable")
