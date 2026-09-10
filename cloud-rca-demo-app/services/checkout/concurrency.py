"""Inventory deduction — INTENTIONALLY RACY for RCA demos.

Fault RACE-CONDITION: read-modify-write without a lock lets concurrent
checkouts double-deduct (lost update). Fix: lock / atomic compare-and-swap.
"""
import threading

_inventory = {"sku-1": 10}
_lock = threading.Lock()


def deduct_inventory(sku: str, qty: int, use_lock: bool = False):
    """Deduct stock. use_lock=False reproduces the race (default fault)."""
    if use_lock:
        with _lock:
            return _deduct(sku, qty)
    # --- FAULT: unlocked read-modify-write ---
    current = _inventory.get(sku, 0)
    remaining = current - qty
    if remaining < 0:
        raise RuntimeError(f"lost update detected for order (sku={sku} oversell)")
    _inventory[sku] = remaining
    return remaining


def _deduct(sku: str, qty: int):
    current = _inventory.get(sku, 0)
    remaining = current - qty
    if remaining < 0:
        raise RuntimeError(f"lost update detected for order (sku={sku} oversell)")
    _inventory[sku] = remaining
    return remaining
