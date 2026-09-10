"""Incident-scenario tests: each asserts the fixed behavior for a code-fixable RCA.

- pool_exhaustion / bad_deployment / config_regression / dependency_failure
  FAIL on the intentionally faulty code and PASS after the approved patch.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_pool_exhaustion_fixed():
    from services.checkout import database
    assert database.POOL_SIZE >= 10
    assert database.POOL_TIMEOUT >= 5


def test_bad_deployment_fixed():
    from services.checkout import config
    assert config.FEATURE_FLAG_NEW_BILLING is False


def test_config_regression_fixed(monkeypatch):
    import importlib
    monkeypatch.setenv("PAYMENT_GATEWAY_API_KEY", "test-key")
    from services.checkout import config
    importlib.reload(config)
    assert not config.PAYMENT_GATEWAY_HOST.endswith(".invalid"), "gateway host still unroutable"
    assert config.PAYMENT_GATEWAY_API_KEY == "test-key", "env-provided gateway key still ignored"


def test_dependency_timeout_fixed():
    from services.checkout import dependencies
    assert dependencies.ORDERS_TIMEOUT_S >= 5, "downstream timeout still too aggressive"
    assert dependencies.ORDERS_MAX_RETRIES >= 2, "no retry budget for transient downstream slowness"


def test_null_pointer_fixed():
    """payment_processor must guard None profile before attribute access."""
    import inspect
    from services.checkout import payment_processor
    src = inspect.getsource(payment_processor.process_payment)
    assert "payment_profile is None" in src or "PaymentProfileNotFound" in src, \
        "None guard missing in process_payment"


def test_contract_mismatch_fixed():
    import json
    from services.orders import contract
    out = contract.serialize_order({"id": "ord-1"})
    json.loads(out)  # must not raise TypeError


def test_race_condition_fixed():
    import inspect
    from services.checkout import concurrency
    src = inspect.getsource(concurrency.deduct_inventory)
    assert "use_lock" in src or "_lock" in src or "compare" in src.lower(), \
        "no locking/compare-and-swap in deduct_inventory"


def test_slow_query_fixed():
    from services.checkout import queries
    import inspect
    src = inspect.getsource(queries.order_history)
    assert "index" in src.lower() or "user_id" in src, "order_history still unindexed"
