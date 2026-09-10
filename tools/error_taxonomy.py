"""
Error domain taxonomy: every scenario/category maps to CODE vs INFRASTRUCTURE
plus a subcategory. Drives simulation grouping, RCA domain display, and
whether the remediation path may propose code changes.
"""
from typing import Dict, Tuple

CODE = "Code / Application"
INFRA = "Infrastructure / Platform"

# scenario slug -> (domain, subcategory)
SCENARIOS: Dict[str, Tuple[str, str]] = {
    "db-timeout": (CODE, "Application Dependency"),
    "pool-exhaustion": (CODE, "Application Resource"),
    "bad-deployment": (CODE, "Configuration"),
    "dependency-failure": (CODE, "Application Dependency"),
    "traffic-overload": (INFRA, "Capacity"),
    "config-error": (CODE, "Configuration"),
    "memory-leak": (INFRA, "Compute"),
    "cpu-exhaustion": (INFRA, "Compute"),
    "auth-failure": (CODE, "Application Logic"),
    "network-timeout": (INFRA, "Network"),
    "malformed-payload": (CODE, "Application Logic"),
    "rate-limit": (INFRA, "Quota"),
}

# RCA category -> (domain, subcategory); unknown stays honest
CATEGORIES: Dict[str, Tuple[str, str]] = {
    "database_connectivity": (CODE, "Application Dependency"),
    "connection_pool_exhaustion": (CODE, "Application Resource"),
    "faulty_revision": (CODE, "Configuration"),
    "dependency_failure": (CODE, "Application Dependency"),
    "traffic_overload": (INFRA, "Capacity"),
    "configuration_regression": (CODE, "Configuration"),
    "latency_degradation": (INFRA, "Capacity"),
    "memory_leak": (INFRA, "Compute"),
    "cpu_exhaustion": (INFRA, "Compute"),
    "auth_failure": (CODE, "Application Logic"),
    "network_timeout": (INFRA, "Network"),
    "malformed_payload": (CODE, "Application Logic"),
    "rate_limit": (INFRA, "Quota"),
    "unknown": ("Unknown", "Unknown"),
}

# simulation groups for the dashboard
GROUPS = {
    "code": {
        "title": "Code / Application Errors",
        "subgroups": {
            "Configuration": ["bad-deployment", "config-error"],
            "Application Logic": ["malformed-payload", "auth-failure"],
            "Application Dependency": ["dependency-failure", "db-timeout"],
            "Application Resource": ["pool-exhaustion"],
        },
    },
    "infra": {
        "title": "Infrastructure / Platform Errors",
        "subgroups": {
            "Compute": ["cpu-exhaustion", "memory-leak"],
            "Network": ["network-timeout"],
            "Capacity": ["traffic-overload"],
            "Quota": ["rate-limit"],
        },
    },
}

LABELS = {
    "db-timeout": "DB Timeout",
    "pool-exhaustion": "Pool Exhaustion",
    "bad-deployment": "Bad Deployment",
    "dependency-failure": "Dependency Failure",
    "traffic-overload": "Traffic Overload",
    "config-error": "Config Error",
    "memory-leak": "Memory Leak",
    "cpu-exhaustion": "CPU Exhaustion",
    "auth-failure": "Auth Failure",
    "network-timeout": "Network Timeout",
    "malformed-payload": "Malformed Input",
    "rate-limit": "Rate Limit",
}


def domain_for_category(category: str) -> Tuple[str, str]:
    return CATEGORIES.get(category or "unknown", ("Unknown", "Unknown"))


def domain_for_scenario(scenario: str) -> Tuple[str, str]:
    return SCENARIOS.get(scenario, ("Unknown", "Unknown"))


def code_fix_allowed(domain: str) -> bool:
    return domain == CODE
