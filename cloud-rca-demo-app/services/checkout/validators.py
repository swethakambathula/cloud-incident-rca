"""Cart schema validation — INTENTIONALLY STRICT for RCA demos.

Fault INVALID-PAYLOAD: zero/negative amounts raise schema validation
failures instead of being coerced. Fix: validate early with a clear 400.
"""


def validate_cart(items):
    if not items:
        raise ValueError("schema validation failure: cart must not be empty")
    for item in items:
        amount = item.get("amount_cents", item.get("price", 0) * item.get("qty", 0))
        if amount <= 0:
            raise ValueError(
                "schema validation failure: amount_cents must be positive")
    return True
