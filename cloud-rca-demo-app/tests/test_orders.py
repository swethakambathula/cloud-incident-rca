"""Orders service tests."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.orders import main, database


def test_create_order_healthy(monkeypatch):
    monkeypatch.setattr(database, "is_down", lambda: False)
    monkeypatch.setattr(database, "insert_order", lambda p: {"id": "ord-1"})
    assert main.create_order({"item": "book"})["status"] == 201


def test_create_order_reports_503_when_db_down(monkeypatch):
    monkeypatch.setattr(database, "is_down", lambda: True)
    assert main.create_order({})["status"] == 503
