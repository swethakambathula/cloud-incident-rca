"""
Generalized live incident log generator (Part 2).

Produces structured JSON logs with baseline (healthy) + incident phases for
all supported failure types. Each log carries the full telemetry schema so the
RCA pipeline can correlate logs, metrics, traces and dependencies.
"""
import random
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

SEVERITIES = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# scenario -> telemetry spec. latency/cpu/mem/pool describe the INCIDENT phase;
# baseline_* describe the healthy phase. incident_file maps to a static
# data/incidents/*.json when one exists (None = evidence built purely live).
SCENARIO_SPECS: Dict[str, Dict[str, Any]] = {
    "db-timeout": dict(incident_type="DB_TIMEOUT", error_code="DATABASE_CONNECTION_TIMEOUT",
        severity="ERROR", status_code=500, latency_ms=5020, service="checkout-service",
        endpoint="/checkout", dependency="orders-db", cpu=24.0, memory=39.5, pool=35,
        incident_file="incident_001_db_timeout.json",
        message="could not connect to orders-db.internal:5432 after 5000ms"),
    "pool-exhaustion": dict(incident_type="POOL_EXHAUSTION", error_code="DATABASE_CONNECTION_POOL_EXHAUSTED",
        severity="ERROR", status_code=500, latency_ms=4800, service="checkout-service",
        endpoint="/checkout", dependency="orders-db", cpu=27.0, memory=44.0, pool=100,
        incident_file="incident_002_pool_exhaustion.json",
        message="pool_usage=100% active=50 max=50 waiting_threads=45"),
    "bad-deployment": dict(incident_type="BAD_DEPLOYMENT", error_code="NULL_POINTER_EXCEPTION",
        severity="ERROR", status_code=500, latency_ms=220, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=21.0, memory=36.0, pool=20,
        incident_file="incident_003_bad_deployment.json",
        message="NullPointerException in PaymentProcessor.java:84 at checkout-service-00005-bad"),
    "dependency-failure": dict(incident_type="DEPENDENCY_FAILURE", error_code="DOWNSTREAM_DEPENDENCY_FAILURE",
        severity="ERROR", status_code=502, latency_ms=1150, service="checkout-service",
        endpoint="/checkout", dependency="orders-service", cpu=22.5, memory=37.0, pool=30,
        incident_file="incident_004_dependency_outage.json",
        message="dependency=orders-service status=503 upstream connect error"),
    "traffic-overload": dict(incident_type="TRAFFIC_OVERLOAD", error_code="REQUEST_QUEUE_FULL_THROTTLED",
        severity="WARNING", status_code=503, latency_ms=4200, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=96.0, memory=88.0, pool=85,
        incident_file="incident_005_traffic_overload.json",
        message="max_concurrent_requests_exceeded instances=10 (max_instances reached)"),
    "config-error": dict(incident_type="CONFIG_REGRESSION", error_code="CONFIGURATION_REGRESSION",
        severity="ERROR", status_code=500, latency_ms=165, service="checkout-service",
        endpoint="/simulate/config-error", dependency="none", cpu=19.0, memory=35.0, pool=10,
        incident_file="incident_006_config_regression.json",
        message="Required environment variable PAYMENT_GATEWAY_API_KEY is missing or empty"),
    "memory-leak": dict(incident_type="MEMORY_LEAK", error_code="MEMORY_PRESSURE_OOM_RISK",
        severity="CRITICAL", status_code=500, latency_ms=900, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=45.0, memory=93.0, pool=40,
        incident_file=None,
        message="memory usage 93% climbing 2%/min, GC thrashing, OOM risk on instance 3"),
    "cpu-exhaustion": dict(incident_type="CPU_EXHAUSTION", error_code="CPU_SATURATION_THROTTLED",
        severity="WARNING", status_code=503, latency_ms=3800, service="checkout-service",
        endpoint="/simulate/cpu", dependency="none", cpu=98.0, memory=60.0, pool=50,
        incident_file=None,
        message="compute-heavy endpoint saturating vCPU, queue wait 3800ms"),
    "auth-failure": dict(incident_type="AUTH_FAILURE", error_code="AUTH_FAILURE",
        severity="ERROR", status_code=401, latency_ms=120, service="payments-service",
        endpoint="/charge", dependency="none", cpu=18.0, memory=33.0, pool=5,
        incident_file=None,
        message="invalid or expired gateway credentials (HTTP 401)"),
    "network-timeout": dict(incident_type="NETWORK_TIMEOUT", error_code="DOWNSTREAM_TIMEOUT",
        severity="ERROR", status_code=504, latency_ms=5000, service="checkout-service",
        endpoint="/checkout", dependency="orders-service", cpu=23.0, memory=38.0, pool=25,
        incident_file=None,
        message="downstream call timed out after 5000ms, no CPU/memory anomaly"),
    "malformed-payload": dict(incident_type="MALFORMED_PAYLOAD", error_code="MALFORMED_PAYLOAD",
        severity="WARNING", status_code=400, latency_ms=60, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=20.0, memory=35.0, pool=8,
        incident_file=None,
        message="request validation failed: amount_cents must be positive (HTTP 400)"),
    "rate-limit": dict(incident_type="RATE_LIMIT", error_code="RATE_LIMIT_EXCEEDED",
        severity="WARNING", status_code=429, latency_ms=80, service="payments-service",
        endpoint="/charge", dependency="none", cpu=22.0, memory=36.0, pool=12,
        incident_file=None,
        message="quota exceeded: 429 burst detected, retry after 60s"),
    # Tier-1 code/application simulations (additive; legacy slugs unchanged)
    "null-pointer": dict(incident_type="NULL_POINTER", error_code="AttributeError: 'NoneType' object has no attribute 'amount'",
        severity="ERROR", status_code=500, latency_ms=240, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=21.0, memory=36.0, pool=20,
        incident_file=None,
        message="AttributeError: 'NoneType' object has no attribute 'amount' at services/checkout/payment_processor.py:24 in process_payment"),
    "key-error": dict(incident_type="KEY_ERROR", error_code="KeyError: 'payment_method'",
        severity="ERROR", status_code=500, latency_ms=230, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=21.0, memory=36.0, pool=20,
        incident_file="incident_003_bad_deployment.json",
        message="KeyError: 'payment_method' at services/checkout/main.py:9 in _new_billing_total"),
    "invalid-payload": dict(incident_type="INVALID_PAYLOAD", error_code="ValueError: schema validation failure",
        severity="WARNING", status_code=400, latency_ms=60, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=20.0, memory=35.0, pool=8,
        incident_file=None,
        message="schema validation failure: amount_cents must be positive at services/checkout/validators.py:14"),
    "feature-flag-regression": dict(incident_type="FEATURE_FLAG_REGRESSION", error_code="KeyError: 'nonexistent_fee'",
        severity="ERROR", status_code=500, latency_ms=220, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=21.0, memory=36.0, pool=20,
        incident_file="incident_003_bad_deployment.json",
        message="FEATURE_FLAG_NEW_BILLING enabled broken path at services/checkout/config.py:9"),
    "dependency-timeout": dict(incident_type="DEPENDENCY_TIMEOUT", error_code="DOWNSTREAM_DEPENDENCY_FAILURE",
        severity="ERROR", status_code=502, latency_ms=1150, service="checkout-service",
        endpoint="/checkout", dependency="orders-service", cpu=22.5, memory=37.0, pool=30,
        incident_file="incident_004_dependency_outage.json",
        message="dependency=orders-service status=503 upstream connect error timeout=1s"),
    "api-contract-mismatch": dict(incident_type="CONTRACT_MISMATCH", error_code="TypeError: Object of type Decimal is not JSON serializable",
        severity="ERROR", status_code=502, latency_ms=300, service="checkout-service",
        endpoint="/checkout", dependency="orders-service", cpu=22.0, memory=37.0, pool=25,
        incident_file=None,
        message="TypeError: Object of type Decimal is not JSON serializable at services/orders/contract.py:18"),
    "cpu-hot-loop": dict(incident_type="CPU_HOT_LOOP", error_code="CPU_SATURATION_THROTTLED",
        severity="WARNING", status_code=503, latency_ms=3800, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=98.0, memory=60.0, pool=50,
        incident_file=None,
        message="pricing hot loop saturating vCPU at services/checkout/pricing.py:16"),
    "race-condition": dict(incident_type="RACE_CONDITION", error_code="RuntimeError: lost update detected",
        severity="ERROR", status_code=500, latency_ms=400, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=45.0, memory=45.0, pool=40,
        incident_file=None,
        message="lost update detected for order at services/checkout/concurrency.py:20"),
    "missing-env-var": dict(incident_type="CONFIG_REGRESSION", error_code="CONFIGURATION_REGRESSION",
        severity="ERROR", status_code=500, latency_ms=165, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=19.0, memory=35.0, pool=10,
        incident_file="incident_006_config_regression.json",
        message="Required environment variable PAYMENT_GATEWAY_API_KEY is missing or empty"),
    "dependency-version-regression": dict(incident_type="VERSION_REGRESSION", error_code="ImportError: cannot import name 'soft_unicode'",
        severity="ERROR", status_code=500, latency_ms=180, service="checkout-service",
        endpoint="/checkout", dependency="none", cpu=20.0, memory=36.0, pool=15,
        incident_file=None,
        message="ImportError: cannot import name 'soft_unicode' from 'markupsafe' (requirements.txt unpinned)"),
    "slow-query": dict(incident_type="SLOW_QUERY", error_code="QUERY_SLOW p95 4800ms",
        severity="ERROR", status_code=500, latency_ms=4800, service="checkout-service",
        endpoint="/checkout", dependency="orders-db", cpu=35.0, memory=50.0, pool=60,
        incident_file="incident_001_db_timeout.json",
        message="QUERY_SLOW p95 4800ms on order_history seq scan at services/checkout/queries.py:17"),
}


def _base_fields(spec: Dict[str, Any], incident_id: str, revision: str, region: str) -> Dict[str, Any]:
    return {
        "service_name": spec["service"],
        "revision": revision,
        "environment": "production",
        "incident_id": incident_id,
        "incident_type": spec["incident_type"],
        "request_id": f"req-{uuid.uuid4().hex[:12]}",
        "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
        "span_id": f"span-{uuid.uuid4().hex[:8]}",
        "endpoint": spec["endpoint"],
        "method": "POST" if spec["endpoint"] in ("/checkout", "/charge", "/orders") else "GET",
        "dependency": spec["dependency"],
        "region": region,
        "retry_count": 0,
    }


def generate_logs(scenario: str, incident_id: str = None, n_baseline: int = 8,
                  n_incident: int = 25, revision: str = None,
                  region: str = "us-central1", seed: int = None) -> List[Dict[str, Any]]:
    """Baseline INFO logs followed by incident-phase logs for a scenario."""
    if scenario not in SCENARIO_SPECS:
        raise ValueError(f"Unknown scenario {scenario}. Choose {sorted(SCENARIO_SPECS)}")
    spec = SCENARIO_SPECS[scenario]
    rng = random.Random(seed if seed is not None else hash((scenario, incident_id or "")) % (2 ** 31))
    incident_id = incident_id or f"INC-LIVE-{spec['incident_type']}"
    revision = revision or "checkout-service-00005-bad" if scenario == "bad-deployment" else (revision or "checkout-service-00004-v1")
    now = datetime.now(timezone.utc)
    logs: List[Dict[str, Any]] = []

    def jitter(v: float, pct: float = 0.1) -> float:
        return round(v * (1 + rng.uniform(-pct, pct)), 1)

    # Baseline: healthy traffic
    for i in range(n_baseline):
        logs.append({
            **_base_fields(spec, incident_id, revision, region),
            "timestamp": (now - timedelta(minutes=10) + timedelta(seconds=i * 5)).isoformat(),
            "severity": "INFO",
            "status_code": 200,
            "latency_ms": int(jitter(150, 0.2)),
            "error_code": "",
            "message": f"request completed {spec['endpoint']} 200 in ~150ms",
            "cpu_percent": jitter(20.0), "memory_percent": jitter(35.0),
            "connection_pool_usage": int(jitter(25.0)), "retry_count": 0,
            "scenario": scenario,
        })
    # Incident phase
    for i in range(n_incident):
        sev = spec["severity"]
        # sprinkle a couple of WARNING/INFO lines for realism
        if rng.random() < 0.12:
            sev = "WARNING"
        logs.append({
            **_base_fields(spec, incident_id, revision, region),
            "timestamp": (now - timedelta(seconds=(n_incident - i) * 4)).isoformat(),
            "severity": sev,
            "status_code": spec["status_code"],
            "latency_ms": int(jitter(spec["latency_ms"], 0.15)),
            "error_code": spec["error_code"],
            "message": f"{spec['error_code']} {spec['message']}",
            "cpu_percent": jitter(spec["cpu"]), "memory_percent": jitter(spec["memory"]),
            "connection_pool_usage": int(jitter(spec["pool"])),
            "retry_count": rng.choice([0, 0, 1]),
            "scenario": scenario,
        })
    return logs


def _p95(values: List[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = min(len(s) - 1, int(0.95 * len(s)))
    return round(float(s[idx]), 1)


def summarize(logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Dashboard summary row: totals, rates, p95, resources, revision, duration."""
    if not logs:
        return {"total_requests": 0, "error_5xx_rate_pct": 0.0, "error_4xx_rate_pct": 0.0,
                "p95_latency_ms": 0.0, "avg_cpu_pct": 0.0, "avg_memory_pct": 0.0,
                "active_revision": "-", "incident_duration_s": 0}
    total = len(logs)
    n5xx = sum(1 for l in logs if 500 <= int(l.get("status_code", 200)) <= 599)
    n4xx = sum(1 for l in logs if 400 <= int(l.get("status_code", 200)) <= 499)
    lats = [float(l.get("latency_ms", 0)) for l in logs]
    cpus = [float(l.get("cpu_percent", 0)) for l in logs]
    mems = [float(l.get("memory_percent", 0)) for l in logs]
    revs = [l.get("revision", "-") for l in logs if l.get("severity") in ("ERROR", "CRITICAL", "WARNING")]
    try:
        dur = (datetime.fromisoformat(logs[-1]["timestamp"]) - datetime.fromisoformat(logs[0]["timestamp"])).total_seconds()
    except Exception:
        dur = 0
    return {
        "total_requests": total,
        "error_5xx_rate_pct": round(100 * n5xx / total, 1),
        "error_4xx_rate_pct": round(100 * n4xx / total, 1),
        "p95_latency_ms": _p95(lats),
        "avg_cpu_pct": round(sum(cpus) / len(cpus), 1),
        "avg_memory_pct": round(sum(mems) / len(mems), 1),
        "active_revision": max(set(revs), key=revs.count) if revs else "-",
        "incident_duration_s": int(dur),
    }
