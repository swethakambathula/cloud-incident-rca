"""Orders response contract — INTENTIONALLY MISMATCHED for RCA demos.

Fault CONTRACT-MISMATCH: serialize_order returns Decimal objects that the
pinned json encoder cannot handle. Fix: convert Decimal -> str/float.
"""
import json
from decimal import Decimal


def serialize_order(order: dict) -> str:
    """Serialize an order. Fault: Decimal leaks into json.dumps."""
    payload = dict(order)
    # --- FAULT: Decimal not JSON serializable ---
    if "total" not in payload:
        payload["total"] = Decimal("19.99")
    return json.dumps(payload)
