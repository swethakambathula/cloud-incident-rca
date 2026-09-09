"""Payments service configuration."""
import os

GATEWAY_HOST = os.getenv("PAYMENT_GATEWAY_HOST", "payments.invalid")
GATEWAY_TIMEOUT_S = int(os.getenv("GATEWAY_TIMEOUT_S", "5"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
