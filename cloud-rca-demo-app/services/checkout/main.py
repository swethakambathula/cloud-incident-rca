"""Checkout service entrypoints."""
from . import config
from . import database
from . import dependencies


def _new_billing_total(items):
    # --- FAULT (bad-deployment): new billing path dereferences a missing key ---
    return sum(i["price"] * i["qty"] for i in items) + items[0]["nonexistent_fee"]


def _legacy_billing_total(items):
    return sum(i["price"] * i["qty"] for i in items)


def checkout(cart_items, order_payload):
    """POST /checkout handler. May raise per injected fault scenario."""
    if config.FEATURE_FLAG_NEW_BILLING:
        total = _new_billing_total(cart_items)  # raises KeyError on faulty revision
    else:
        total = _legacy_billing_total(cart_items)
    history = database.query_order_history(order_payload.get("user_id", "anon"))
    order = dependencies.create_order(order_payload)
    return {"total": total, "history": history, "order": order}


def health():
    return {"status": "ok", "service": "checkout-service"}
