"""Tier-1 simulation catalog: 15 fully-implemented demo scenarios.

Each entry defines ground truth (service, file, function, error signature,
fix type, confidence range, required evidence) plus evidence generation that
produces realistic logs: baseline healthy traffic, incident-phase HTTP 500s,
stack traces with file/line, request/trace IDs, deployment metadata, and
metric fields so RCA can genuinely correlate.
"""
from typing import Dict, List

TIER1_CATEGORIES = ("Code", "Database", "Dependency", "Runtime", "Concurrency", "Deployment")

# scenario_id -> ground truth
TIER1: Dict[str, Dict] = {
    "null-pointer": {
        "scenario_id": "null-pointer", "category": "Code", "subcategory": "Null Handling",
        "service": "checkout-service", "root_cause": "NULL_POINTER",
        "rca_category": "null_pointer", "file": "services/checkout/payment_processor.py",
        "function": "process_payment", "line": 24,
        "error_signature": "AttributeError: 'NoneType' object has no attribute 'amount'",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.85, 0.98],
        "required_evidence": ["logs", "stack_trace", "http_metrics", "deployment_metadata"],
        "optional_evidence": ["traces"],
        "title": "Null Pointer / NoneType",
        "blurb": "Unhandled null object in the checkout payment path.",
        "evidence": "Logs - stack trace - HTTP metrics - deployment metadata",
        "expected_rca": "payment_processor.py null handling regression",
        "revision": "checkout-service-00005-bad",
        "stack_trace": (
            'Traceback (most recent call last):\n'
            '  File "services/checkout/api.py", line 112, in post_checkout\n'
            '    result = process_payment(payload)\n'
            '  File "services/checkout/payment_processor.py", line 24, in process_payment\n'
            '    amount = payment_profile.amount\n'
            "AttributeError: 'NoneType' object has no attribute 'amount'"
        ),
    },
    "key-error": {
        "scenario_id": "key-error", "category": "Code", "subcategory": "Null Handling",
        "service": "checkout-service", "root_cause": "MISSING_KEY",
        "rca_category": "faulty_revision", "file": "services/checkout/main.py",
        "function": "_new_billing_total", "line": 9,
        "error_signature": "KeyError: 'payment_method'",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.85, 0.97],
        "required_evidence": ["logs", "stack_trace", "http_metrics", "deployment_metadata"],
        "optional_evidence": ["traces"],
        "title": "Missing Dictionary Key",
        "blurb": "New billing path dereferences a key absent from legacy carts.",
        "evidence": "Logs - stack trace - HTTP metrics - deployment metadata",
        "expected_rca": "main.py missing-key regression on faulty revision",
        "revision": "checkout-service-00005-bad",
        "stack_trace": (
            'Traceback (most recent call last):\n'
            '  File "services/checkout/main.py", line 19, in checkout\n'
            '    total = _new_billing_total(cart_items)\n'
            '  File "services/checkout/main.py", line 9, in _new_billing_total\n'
            '    return sum(i["price"] * i["qty"] for i in items) + items[0]["nonexistent_fee"]\n'
            "KeyError: 'payment_method'"
        ),
    },
    "invalid-payload": {
        "scenario_id": "invalid-payload", "category": "Code", "subcategory": "Validation",
        "service": "checkout-service", "root_cause": "SCHEMA_VALIDATION",
        "rca_category": "malformed_payload", "file": "services/checkout/validators.py",
        "function": "validate_cart", "line": 14,
        "error_signature": "ValueError: schema validation failure: amount_cents must be positive",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.8, 0.95],
        "required_evidence": ["logs", "http_metrics"],
        "optional_evidence": ["traces"],
        "title": "Invalid Payload",
        "blurb": "Upstream carts fail strict schema validation at checkout.",
        "evidence": "Logs - HTTP 400 metrics - validation errors",
        "expected_rca": "validators.py rejecting malformed carts",
        "revision": "checkout-service-00004-v1",
        "stack_trace": (
            'Traceback (most recent call last):\n'
            '  File "services/checkout/validators.py", line 14, in validate_cart\n'
            '    raise ValueError("schema validation failure: amount_cents must be positive")\n'
            'ValueError: schema validation failure: amount_cents must be positive'
        ),
    },
    "feature-flag-regression": {
        "scenario_id": "feature-flag-regression", "category": "Code", "subcategory": "Application Logic",
        "service": "checkout-service", "root_cause": "FEATURE_FLAG_REGRESSION",
        "rca_category": "faulty_revision", "file": "services/checkout/config.py",
        "function": "", "line": 9,
        "error_signature": "KeyError: 'nonexistent_fee' behind FEATURE_FLAG_NEW_BILLING",
        "fix_type": "CONFIG_CHANGE", "confidence_range": [0.85, 0.97],
        "required_evidence": ["logs", "stack_trace", "deployment_metadata"],
        "optional_evidence": ["http_metrics"],
        "title": "Feature Flag Regression",
        "blurb": "New billing flag enabled a broken code path on the latest revision.",
        "evidence": "Logs - stack trace - deployment metadata",
        "expected_rca": "FEATURE_FLAG_NEW_BILLING regression in config.py",
        "revision": "checkout-service-00005-bad",
        "stack_trace": (
            'Traceback (most recent call last):\n'
            '  File "services/checkout/main.py", line 19, in checkout\n'
            '    total = _new_billing_total(cart_items)\n'
            "KeyError: 'nonexistent_fee'"
        ),
    },
    "db-timeout": {
        "scenario_id": "db-timeout", "category": "Database", "subcategory": "Persistence",
        "service": "checkout-service", "root_cause": "DB_TIMEOUT",
        "rca_category": "database_connectivity", "file": "services/checkout/database.py",
        "function": "query_order_history", "line": 56,
        "error_signature": "DATABASE_CONNECTION_TIMEOUT",
        "fix_type": "INFRA_ACTION", "confidence_range": [0.8, 0.95],
        "required_evidence": ["logs", "http_metrics", "dependency_signals"],
        "optional_evidence": ["traces"],
        "title": "DB Timeout",
        "blurb": "Orders database unreachable; checkout queries time out.",
        "evidence": "Logs - dependency signals - HTTP metrics",
        "expected_rca": "database connectivity to orders-db",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "TimeoutError: could not connect to orders-db.internal:5432 after 5000ms",
    },
    "pool-exhaustion": {
        "scenario_id": "pool-exhaustion", "category": "Database", "subcategory": "Persistence",
        "service": "checkout-service", "root_cause": "POOL_EXHAUSTED",
        "rca_category": "connection_pool_exhaustion", "file": "services/checkout/database.py",
        "function": "acquire_connection", "line": 37,
        "error_signature": "DATABASE_CONNECTION_POOL_EXHAUSTED",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.85, 0.97],
        "required_evidence": ["logs", "http_metrics", "pool_gauge"],
        "optional_evidence": ["traces"],
        "title": "Connection Pool Exhaustion",
        "blurb": "Undersized DB pool saturates under normal concurrency.",
        "evidence": "Logs - pool gauge - HTTP metrics",
        "expected_rca": "database.py pool sizing regression",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "TimeoutError: DATABASE_CONNECTION_POOL_EXHAUSTED pool_usage=100% waiting_threads>0",
    },
    "dependency-timeout": {
        "scenario_id": "dependency-timeout", "category": "Dependency", "subcategory": "Downstream",
        "service": "checkout-service", "root_cause": "DOWNSTREAM_TIMEOUT",
        "rca_category": "dependency_failure", "file": "services/checkout/dependencies.py",
        "function": "create_order", "line": 20,
        "error_signature": "DOWNSTREAM_DEPENDENCY_FAILURE dependency=orders-service",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.82, 0.96],
        "required_evidence": ["logs", "dependency_signals", "http_metrics"],
        "optional_evidence": ["traces"],
        "title": "Dependency Timeout",
        "blurb": "Orders-service p99 slowness exceeds the 1s checkout timeout.",
        "evidence": "Logs - dependency latency - HTTP metrics",
        "expected_rca": "dependencies.py aggressive timeout, no retries",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "DependencyError: DOWNSTREAM_DEPENDENCY_FAILURE dependency=orders-service timeout=1s",
    },
    "api-contract-mismatch": {
        "scenario_id": "api-contract-mismatch", "category": "Dependency", "subcategory": "Contract",
        "service": "checkout-service", "root_cause": "CONTRACT_MISMATCH",
        "rca_category": "dependency_failure", "file": "services/orders/contract.py",
        "function": "serialize_order", "line": 18,
        "error_signature": "TypeError: Object of type Decimal is not JSON serializable",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.8, 0.95],
        "required_evidence": ["logs", "stack_trace", "dependency_signals"],
        "optional_evidence": ["http_metrics"],
        "title": "API Contract Mismatch",
        "blurb": "Orders-service changed its response schema without versioning.",
        "evidence": "Logs - stack trace - dependency signals",
        "expected_rca": "orders contract serialization mismatch",
        "revision": "checkout-service-00004-v1",
        "stack_trace": (
            'Traceback (most recent call last):\n'
            '  File "services/orders/contract.py", line 18, in serialize_order\n'
            '    return json.dumps(order)\n'
            'TypeError: Object of type Decimal is not JSON serializable'
        ),
    },
    "memory-leak": {
        "scenario_id": "memory-leak", "category": "Runtime", "subcategory": "Resources",
        "service": "checkout-service", "root_cause": "MEMORY_LEAK",
        "rca_category": "memory_leak", "file": "services/checkout/cache.py",
        "function": "put", "line": 22,
        "error_signature": "MEMORY_PRESSURE_OOM_RISK",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.75, 0.92],
        "required_evidence": ["logs", "memory_metrics"],
        "optional_evidence": ["http_metrics"],
        "title": "Memory Leak",
        "blurb": "Unbounded in-process cache grows until OOM risk.",
        "evidence": "Logs - memory metrics - GC signals",
        "expected_rca": "cache.py unbounded growth",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "MemoryError: memory usage 93% climbing 2%/min, GC thrashing",
    },
    "cpu-hot-loop": {
        "scenario_id": "cpu-hot-loop", "category": "Runtime", "subcategory": "Resources",
        "service": "checkout-service", "root_cause": "CPU_HOT_LOOP",
        "rca_category": "cpu_exhaustion", "file": "services/checkout/pricing.py",
        "function": "price_cart", "line": 16,
        "error_signature": "CPU_SATURATION_THROTTLED",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.75, 0.92],
        "required_evidence": ["logs", "cpu_metrics"],
        "optional_evidence": ["http_metrics"],
        "title": "CPU Hot Loop",
        "blurb": "Inefficient pricing loop saturates vCPU under load.",
        "evidence": "Logs - CPU metrics - latency signals",
        "expected_rca": "pricing.py hot loop",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "TimeoutError: CPU_SATURATION_THROTTLED queue wait 3800ms",
    },
    "race-condition": {
        "scenario_id": "race-condition", "category": "Concurrency", "subcategory": "Race",
        "service": "checkout-service", "root_cause": "RACE_CONDITION",
        "rca_category": "race_condition", "file": "services/checkout/concurrency.py",
        "function": "deduct_inventory", "line": 20,
        "error_signature": "RuntimeError: lost update detected for order",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.75, 0.92],
        "required_evidence": ["logs", "duplicate_events"],
        "optional_evidence": ["traces"],
        "title": "Race Condition",
        "blurb": "Concurrent checkouts double-deduct inventory (lost update).",
        "evidence": "Logs - duplicate events - trace ordering",
        "expected_rca": "concurrency.py missing lock around inventory",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "RuntimeError: lost update detected for order_id=ord-123 (version conflict)",
    },
    "bad-deployment": {
        "scenario_id": "bad-deployment", "category": "Deployment", "subcategory": "Release",
        "service": "checkout-service", "root_cause": "BAD_DEPLOYMENT",
        "rca_category": "faulty_revision", "file": "services/checkout/config.py",
        "function": "", "line": 9,
        "error_signature": "NULL_POINTER_EXCEPTION in PaymentProcessor.java:84",
        "fix_type": "ROLLBACK", "confidence_range": [0.85, 0.97],
        "required_evidence": ["logs", "stack_trace", "deployment_metadata"],
        "optional_evidence": ["http_metrics"],
        "title": "Bad Deployment",
        "blurb": "Latest revision introduced a crash minutes before the incident.",
        "evidence": "Logs - deployment metadata - revision diff",
        "expected_rca": "faulty revision checkout-service-00005-bad",
        "revision": "checkout-service-00005-bad",
        "stack_trace": "NullPointerException in PaymentProcessor.java:84 at checkout-service-00005-bad",
    },
    "missing-env-var": {
        "scenario_id": "missing-env-var", "category": "Deployment", "subcategory": "Configuration",
        "service": "checkout-service", "root_cause": "MISSING_ENV_VAR",
        "rca_category": "configuration_regression", "file": "services/checkout/config.py",
        "function": "validate", "line": 15,
        "error_signature": "CONFIGURATION_REGRESSION: PAYMENT_GATEWAY_API_KEY is missing",
        "fix_type": "CONFIG_CHANGE", "confidence_range": [0.85, 0.97],
        "required_evidence": ["logs", "config_snapshot"],
        "optional_evidence": ["deployment_metadata"],
        "title": "Missing Environment Variable",
        "blurb": "Gateway credentials absent in the deployed environment.",
        "evidence": "Logs - config snapshot - deployment metadata",
        "expected_rca": "config.py missing PAYMENT_GATEWAY_API_KEY",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "RuntimeError: CONFIGURATION_REGRESSION: Required environment variable PAYMENT_GATEWAY_API_KEY is missing or empty",
    },
    "dependency-version-regression": {
        "scenario_id": "dependency-version-regression", "category": "Deployment", "subcategory": "Dependencies",
        "service": "checkout-service", "root_cause": "VERSION_REGRESSION",
        "rca_category": "dependency_version_regression", "file": "requirements.txt",
        "function": "", "line": 3,
        "error_signature": "ImportError: cannot import name 'soft_unicode' from 'markupsafe'",
        "fix_type": "CONFIG_CHANGE", "confidence_range": [0.78, 0.93],
        "required_evidence": ["logs", "deployment_metadata", "build_manifest"],
        "optional_evidence": ["stack_trace"],
        "title": "Dependency Version Regression",
        "blurb": "Unpinned transitive dependency broke imports after deploy.",
        "evidence": "Logs - build manifest - deployment metadata",
        "expected_rca": "requirements.txt unpinned markupsafe/jinja2",
        "revision": "checkout-service-00005-bad",
        "stack_trace": "ImportError: cannot import name 'soft_unicode' from 'markupsafe'",
    },
    "slow-query": {
        "scenario_id": "slow-query", "category": "Database", "subcategory": "Persistence",
        "service": "checkout-service", "root_cause": "SLOW_QUERY",
        "rca_category": "slow_query", "file": "services/checkout/queries.py",
        "function": "order_history", "line": 17,
        "error_signature": "QUERY_SLOW p95 4800ms on order_history",
        "fix_type": "CODE_CHANGE", "confidence_range": [0.78, 0.93],
        "required_evidence": ["logs", "latency_metrics"],
        "optional_evidence": ["traces"],
        "title": "Slow Query",
        "blurb": "Unindexed order-history query regresses checkout latency.",
        "evidence": "Logs - latency metrics - query plan",
        "expected_rca": "queries.py full-table scan on orders",
        "revision": "checkout-service-00004-v1",
        "stack_trace": "TimeoutError: QUERY_SLOW p95 4800ms on order_history (seq scan on orders)",
    },
}

# Legacy slugs still accepted by old buttons -> tier1 ids
LEGACY_ALIASES = {
    "db-timeout": "db-timeout", "pool-exhaustion": "pool-exhaustion",
    "bad-deployment": "bad-deployment", "dependency-failure": "dependency-timeout",
    "traffic-overload": "cpu-hot-loop", "config-error": "missing-env-var",
    "memory-leak": "memory-leak", "cpu-exhaustion": "cpu-hot-loop",
    "auth-failure": "invalid-payload", "network-timeout": "dependency-timeout",
    "malformed-payload": "invalid-payload", "rate-limit": "api-contract-mismatch",
}

ALLOWED_SIM_ENVS = ("demo", "local", "test")


def catalog() -> List[Dict]:
    return [{k: v[k] for k in (
        "scenario_id", "category", "subcategory", "title", "blurb",
        "evidence", "expected_rca", "service", "file", "function",
        "error_signature", "fix_type", "confidence_range",
        "required_evidence", "optional_evidence", "root_cause",
        "rca_category") if k in v} for v in TIER1.values()]


def get(scenario_id: str) -> Dict:
    key = LEGACY_ALIASES.get(scenario_id, scenario_id)
    if key not in TIER1:
        raise KeyError(f"Unknown simulation scenario: {scenario_id}")
    return TIER1[key]


def generate_evidence(scenario_id: str, incident_id: str) -> Dict:
    """Synthetic incident evidence: baseline + incident logs, deployment meta, metrics."""
    import random
    import uuid
    from datetime import datetime, timezone, timedelta
    spec = get(scenario_id)
    rng = random.Random(hash((scenario_id, incident_id)) % (2 ** 31))
    now = datetime.now(timezone.utc)
    logs: List[Dict] = []
    base_rev = "checkout-service-00004-v1"

    def mk(ts, sev, status, lat, msg, cpu=20.0, mem=35.0, pool=25):
        return {
            "timestamp": ts.isoformat(), "severity": sev, "status_code": status,
            "latency_ms": lat, "error_code": spec["error_signature"][:80] if sev in ("ERROR", "CRITICAL") else "",
            "message": msg, "cpu_percent": cpu, "memory_percent": mem,
            "connection_pool_usage": pool, "service_name": spec["service"],
            "revision": spec.get("revision", base_rev), "endpoint": "/checkout",
            "request_id": f"req-{uuid.uuid4().hex[:12]}",
            "trace_id": f"trace-{uuid.uuid4().hex[:12]}",
            "incident_id": incident_id, "scenario": scenario_id,
        }
    for i in range(8):
        logs.append(mk(now - timedelta(minutes=10) + timedelta(seconds=i * 5),
                       "INFO", 200, int(rng.uniform(120, 180)),
                       f"request completed /checkout 200 in ~150ms"))
    for i in range(25):
        sev = "ERROR"
        if rng.random() < 0.12:
            sev = "WARNING"
        status = 500 if spec["category"] in ("Code", "Database", "Concurrency") else (
            400 if scenario_id == "invalid-payload" else 500)
        msg = f"{spec['error_signature']} {spec.get('stack_trace', '')[:220]}"
        logs.append(mk(now - timedelta(seconds=(25 - i) * 4), sev, status,
                       int(rng.uniform(800, 5200)) if spec["category"] != "Code" else int(rng.uniform(150, 400)),
                       msg, cpu=rng.uniform(20, 95), mem=rng.uniform(35, 93), pool=rng.randint(20, 100)))
    return {
        "incident_id": incident_id,
        "scenario_id": scenario_id,
        "service": spec["service"],
        "revision": spec.get("revision", base_rev),
        "previous_revision": base_rev,
        "deployed_at": (now - timedelta(minutes=3)).isoformat(),
        "logs": logs,
        "stack_trace": spec.get("stack_trace", ""),
        "metrics": {"http_5xx_spike": True, "latency_increase": True},
        "ground_truth": {k: spec.get(k) for k in (
            "scenario_id", "category", "subcategory", "service", "root_cause",
            "file", "function", "error_signature", "fix_type")},
    }
