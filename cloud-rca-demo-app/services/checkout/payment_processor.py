"""Checkout payment processing — INTENTIONALLY FAULTY for RCA demos.

Fault NULL-POINTER: payment_profile may be None (guest checkout) and is
dereferenced without a guard. Expected fix: fail fast with
PaymentProfileNotFound before attribute access.
"""
from dataclasses import dataclass


@dataclass
class PaymentProfile:
    profile_id: str
    amount: int


class PaymentProfileNotFound(Exception):
    pass


def load_profile(user_id: str):
    """Returns None for guest/unknown users (fault trigger)."""
    if not user_id or user_id == "guest":
        return None
    return PaymentProfile(profile_id=user_id, amount=1000)


def process_payment(payload: dict):
    """POST /checkout payment path. Raises AttributeError when profile is None."""
    user_id = (payload or {}).get("user_id", "guest")
    payment_profile = load_profile(user_id)
    # --- FAULT: None dereference when payment_profile is None ---
    amount = payment_profile.amount
    return {"charged": amount, "profile": payment_profile.profile_id}
