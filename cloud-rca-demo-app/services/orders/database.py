"""Orders database — toggleable outage for dependency-failure demos."""
import os

ORDERS_DB_HOST = os.getenv("ORDERS_DB_HOST", "orders-db.internal")


def is_down():
    return ORDERS_DB_HOST.endswith(".invalid") or os.getenv("ORDERS_DB_DOWN") == "1"


def insert_order(payload):
    if is_down():
        raise ConnectionError("DATABASE_CONNECTION_TIMEOUT could not connect to orders-db:5432")
    return {"id": "ord-123", "payload": payload}
