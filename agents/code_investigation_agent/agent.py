"""
Code Investigation Agent (Part 5): deterministic repo inspection.

Maps validated RCA categories to suspicious files/lines in cloud-rca-demo-app
via exact pattern search (no LLM invention). Categories without a safe minimal
code fix return no_fix_reason instead of a hallucinated location.
"""
import os
import re
from typing import Dict, List, Optional
from schemas.code_fix import CodeFinding, CodeInvestigation

REPO = "cloud-rca-demo-app"

# category -> list of hunts: file, regex for suspicious assignment, reason, test
HUNTS: Dict[str, List[Dict[str, str]]] = {
    "connection_pool_exhaustion": [
        {"file": "services/checkout/database.py", "pattern": r"^POOL_SIZE\s*=\s*(\S+)",
         "reason": "Pool sized far below concurrent demand while DB stays healthy (pool usage 100%, CPU normal).",
         "test": "tests/test_incident_scenarios.py::test_pool_exhaustion_fixed"},
        {"file": "services/checkout/database.py", "pattern": r"^POOL_TIMEOUT\s*=\s*(\S+)",
         "reason": "Aggressive acquire timeout turns queueing into immediate 500s.",
         "test": "tests/test_incident_scenarios.py::test_pool_exhaustion_fixed"},
    ],
    "faulty_revision": [
        {"file": "services/checkout/config.py", "pattern": r"^FEATURE_FLAG_NEW_BILLING\s*=\s*(\S+)",
         "reason": "New billing path enabled on faulty revision; previous revision (flag off) was healthy.",
         "test": "tests/test_incident_scenarios.py::test_bad_deployment_fixed"},
        {"file": "services/checkout/main.py", "pattern": r"nonexistent_fee",
         "reason": "New billing code dereferences a missing key — the revision-specific crash.",
         "test": "tests/test_incident_scenarios.py::test_bad_deployment_fixed"},
    ],
    "configuration_regression": [
        {"file": "services/checkout/config.py", "pattern": r"^PAYMENT_GATEWAY_HOST\s*=\s*(.+)$",
         "reason": "Hardcoded unroutable gateway host; only config-dependent endpoints fail.",
         "test": "tests/test_incident_scenarios.py::test_config_regression_fixed"},
        {"file": "services/checkout/config.py", "pattern": r"^PAYMENT_GATEWAY_API_KEY\s*=\s*(.*)$",
         "reason": "Environment-provided key ignored (hardcoded empty).",
         "test": "tests/test_incident_scenarios.py::test_config_regression_fixed"},
    ],
    "dependency_failure": [
        {"file": "services/checkout/dependencies.py", "pattern": r"^ORDERS_TIMEOUT_S\s*=\s*(\S+)",
         "reason": "1s downstream timeout with no headroom for p99 orders latency.",
         "test": "tests/test_incident_scenarios.py::test_dependency_timeout_fixed"},
        {"file": "services/checkout/dependencies.py", "pattern": r"^ORDERS_MAX_RETRIES\s*=\s*(\S+)",
         "reason": "Zero retries / no circuit breaker: transient downstream slowness becomes checkout 500s.",
         "test": "tests/test_incident_scenarios.py::test_dependency_timeout_fixed"},
    ],
}

NO_FIX = {
    "database_connectivity": "Database host unreachable (infra/Cloud SQL). No safe code change.",
    "traffic_overload": "Capacity exhaustion (infra scaling). No safe code change.",
    "memory_leak": "Requires heap profiling; no safe minimal patch.",
    "cpu_exhaustion": "Compute saturation (infra). No safe code change.",
    "auth_failure": "Expired credential rotation is an ops/secret task, not a code change.",
    "network_timeout": "Network-level timeout with healthy resources; needs network evidence.",
    "malformed_payload": "Client validation error (4xx). Not an infrastructure outage.",
    "rate_limit": "Quota/policy signal (429). Not an infrastructure outage.",
    "unknown": "Insufficient evidence for a code-level cause.",
}


def repo_root() -> str:
    base = os.getenv("DEMO_APP_PATH") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        REPO)
    return base


class CodeInvestigationAgent:
    agent_name = "Code Investigation Agent"

    def investigate(self, incident_id: str, root_cause_category: str,
                    live_context: Optional[Dict[str, str]] = None) -> CodeInvestigation:
        root = repo_root()
        hunts = HUNTS.get(root_cause_category, [])
        findings: List[CodeFinding] = []
        for hunt in hunts:
            path = os.path.join(root, hunt["file"])
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            for i, line in enumerate(lines, start=1):
                m = re.search(hunt["pattern"], line.strip())
                if m:
                    findings.append(CodeFinding(
                        file=hunt["file"], start_line=i, end_line=i,
                        snippet=line.rstrip(),
                        reason=hunt["reason"],
                        current_value=m.group(1) if m.groups() else None,
                        related_test=hunt["test"],
                    ))
        if not findings:
            return CodeInvestigation(
                incident_id=incident_id, root_cause_category=root_cause_category,
                findings=[],
                no_fix_reason=NO_FIX.get(root_cause_category,
                    "No safe code-level remediation identified."),
            )
        return CodeInvestigation(incident_id=incident_id,
                                 root_cause_category=root_cause_category,
                                 findings=findings)
