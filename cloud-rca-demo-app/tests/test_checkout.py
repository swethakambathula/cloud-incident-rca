"""Checkout service tests — pool/billing expectations for the fixed code."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.checkout import database, main


def test_pool_sized_for_concurrency():
    assert database.POOL_SIZE >= 10, f"POOL_SIZE={database.POOL_SIZE} too small for production concurrency"


def test_pool_timeout_allows_slow_queries():
    assert database.POOL_TIMEOUT >= 5, f"POOL_TIMEOUT={database.POOL_TIMEOUT}s too aggressive"


def test_legacy_billing_path_is_default():
    from services.checkout import config
    assert config.FEATURE_FLAG_NEW_BILLING is False, "broken new billing path must stay off until fixed"


def test_checkout_totals_cart(monkeypatch):
    from services.checkout import config
    import services.checkout.dependencies as deps
    # monkeypatch (auto-reverted): never leak stubs into other tests
    monkeypatch.setattr(config, "FEATURE_FLAG_NEW_BILLING", False)
    monkeypatch.setattr(database, "query_order_history",
                        lambda user_id: {"user_id": user_id, "orders": []})
    monkeypatch.setattr(deps, "create_order",
                        lambda payload: {"status": "created", "attempt": 1})
    out = main.checkout([{"price": 10, "qty": 2}], {"user_id": "u1"})
    assert out["total"] == 20
