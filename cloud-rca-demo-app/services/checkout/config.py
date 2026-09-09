"""Checkout service configuration — INTENTIONALLY FAULTY for RCA demos."""
import os

# --- FAULT (config-regression): hardcoded bad host; env-provided key ignored ---
PAYMENT_GATEWAY_HOST = "payments.invalid"
PAYMENT_GATEWAY_API_KEY = ""

# --- FAULT (bad-deployment): new billing path enabled but broken ---
FEATURE_FLAG_NEW_BILLING = True

DB_STATEMENT_TIMEOUT_MS = 5000
REQUEST_TIMEOUT_S = 30


def validate():
    """Raise CONFIGURATION_REGRESSION when required config is missing/invalid."""
    errors = []
    if not PAYMENT_GATEWAY_API_KEY:
        errors.append("Required environment variable 'PAYMENT_GATEWAY_API_KEY' is missing or empty")
    if PAYMENT_GATEWAY_HOST.endswith(".invalid"):
        errors.append(f"Payment gateway host '{PAYMENT_GATEWAY_HOST}' is not routable")
    if errors:
        raise RuntimeError("CONFIGURATION_REGRESSION: " + "; ".join(errors))
    return True
