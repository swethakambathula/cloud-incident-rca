"""Payments service entrypoints."""
from . import gateway


def charge(amount_cents, token):
    gateway.authenticate(token)
    return gateway.charge(amount_cents)


def health():
    return {"status": "ok", "service": "payments-service"}
