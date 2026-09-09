"""Checkout service database layer — INTENTIONALLY FAULTY for RCA demos.

Fault POOL-EXHAUSTION: pool sized far below concurrent demand.
"""
import queue
import threading
import time

# --- FAULT: pool far too small for production concurrency ---
POOL_SIZE = 2
POOL_TIMEOUT = 1  # seconds to wait for a free connection

# --- FAULT: unreachable database host (infra outage scenario) ---
DB_HOST = "orders-db.invalid"
DB_PORT = 5432

_pool = None
_pool_lock = threading.Lock()


def get_pool():
    global _pool
    with _pool_lock:
        if _pool is None:
            _pool = queue.Queue(maxsize=POOL_SIZE)
            for _ in range(POOL_SIZE):
                _pool.put(object())
        return _pool


def pool_usage_percent():
    pool = get_pool()
    in_use = POOL_SIZE - pool.qsize()
    return int(100 * in_use / POOL_SIZE)


def acquire_connection():
    """Acquire a pooled connection or raise when exhausted (blocks POOL_TIMEOUT)."""
    pool = get_pool()
    try:
        return pool.get(block=True, timeout=POOL_TIMEOUT)
    except queue.Empty:
        raise TimeoutError(
            "DATABASE_CONNECTION_POOL_EXHAUSTED pool_usage=100% "
            "waiting_threads>0"
        )


def release_connection(conn):
    try:
        get_pool().put(conn, block=False)
    except queue.Full:
        pass


def query_order_history(user_id):
    conn = acquire_connection()
    try:
        # Simulated query latency; real impl would use DB_HOST/DB_PORT.
        time.sleep(0.05)
        return {"user_id": user_id, "orders": []}
    finally:
        release_connection(conn)
