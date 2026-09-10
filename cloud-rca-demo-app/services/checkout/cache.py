"""In-process response cache — INTENTIONALLY UNBOUNDED for RCA demos.

Fault MEMORY-LEAK: entries are never evicted, so memory climbs ~2%/min
under traffic. Fix: bound size / add TTL eviction.
"""

_CACHE = {}


def put(key: str, value):
    """Store without eviction (fault)."""
    _CACHE[key] = value
    return len(_CACHE)


def get(key: str):
    return _CACHE.get(key)


def size() -> int:
    return len(_CACHE)
