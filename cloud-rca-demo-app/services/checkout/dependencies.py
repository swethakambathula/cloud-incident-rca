"""Downstream dependency calls — INTENTIONALLY FAULTY for RCA demos.

Fault DEPENDENCY-TIMEOUT: 1s timeout with no retry/circuit breaker, so any
slow orders-service response propagates as checkout 500s.
"""
import time
import urllib.request
import urllib.error

# --- FAULT: timeout too aggressive, no retries, no circuit breaker ---
ORDERS_TIMEOUT_S = 1
ORDERS_MAX_RETRIES = 0
ORDERS_SERVICE_URL = "http://orders-service/orders"


class DependencyError(Exception):
    pass


def create_order(payload, opener=None):
    """Call orders-service. Raises DependencyError (DOWNSTREAM_DEPENDENCY_FAILURE)."""
    last_err = None
    attempts = 1 + ORDERS_MAX_RETRIES
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(
                ORDERS_SERVICE_URL,
                data=str(payload).encode(),
                method="POST",
            )
            with (opener or urllib.request.urlopen)(req, timeout=ORDERS_TIMEOUT_S) as resp:
                if resp.status >= 500:
                    raise DependencyError(
                        f"DOWNSTREAM_DEPENDENCY_FAILURE dependency=orders-service status={resp.status}"
                    )
                return {"status": "created", "attempt": attempt + 1}
        except urllib.error.URLError as e:
            last_err = e
            time.sleep(0)  # no backoff (fault)
    raise DependencyError(
        f"DOWNSTREAM_DEPENDENCY_FAILURE dependency=orders-service "
        f"timeout={ORDERS_TIMEOUT_S}s retries={ORDERS_MAX_RETRIES} last_error={last_err}"
    )
