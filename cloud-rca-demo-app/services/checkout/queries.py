"""Order-history queries — INTENTIONALLY SLOW for RCA demos.

Fault SLOW-QUERY: full-table scan without an index key. Fix: indexed lookup
by user_id with a statement timeout.
"""

ORDERS_TABLE = [{"user_id": f"user-{i % 50}", "id": i} for i in range(20000)]


def order_history(user_id: str):
    """Seq scan over ORDERS_TABLE (fault: no index)."""
    # --- FAULT: full scan instead of indexed lookup ---
    return [o for o in ORDERS_TABLE if o["user_id"] == user_id]
