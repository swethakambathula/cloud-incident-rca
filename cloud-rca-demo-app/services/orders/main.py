"""Orders service — downstream dependency of checkout."""
from . import database


def create_order(payload):
    if database.is_down():
        return {"status": 503, "error": "orders-service unavailable: database unreachable"}
    order = database.insert_order(payload)
    return {"status": 201, "order": order}


def health():
    return {"status": "ok" if not database.is_down() else "degraded", "service": "orders-service"}
