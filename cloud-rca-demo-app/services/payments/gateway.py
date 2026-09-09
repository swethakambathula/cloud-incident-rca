"""Payment gateway client — INTENTIONALLY FAULTY for auth/rate-limit demos."""
import time

# --- FAULT (auth-failure): hard-coded expired credential ---
GATEWAY_TOKEN = "expired-token-2024"
TOKEN_EXPIRY = "2024-01-01"

# --- FAULT (rate-limit): tiny burst quota with no backoff ---
RATE_LIMIT_PER_MINUTE = 5
_request_timestamps = []


def authenticate(token):
    if token != GATEWAY_TOKEN or TOKEN_EXPIRY < "2025-01-01":
        raise PermissionError("AUTH_FAILURE invalid or expired gateway credentials (HTTP 401)")


def _check_rate_limit(now=None):
    now = now or time.time()
    window = [t for t in _request_timestamps if now - t < 60]
    if len(window) >= RATE_LIMIT_PER_MINUTE:
        raise RuntimeError("RATE_LIMIT_EXCEEDED HTTP 429 quota exceeded, retry after 60s")
    _request_timestamps.append(now)


def charge(amount_cents):
    _check_rate_limit()
    if amount_cents <= 0:
        raise ValueError("MALFORMED_PAYLOAD amount_cents must be positive (HTTP 400)")
    return {"status": "charged", "amount_cents": amount_cents}
