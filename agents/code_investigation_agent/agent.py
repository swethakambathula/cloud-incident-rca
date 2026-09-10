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
    "null_pointer": [
        {"file": "services/checkout/payment_processor.py", "pattern": r"^\s*amount\s*=\s*payment_profile\.amount",
         "reason": "Null dereference occurs when payment_profile is None (guest checkout). Stack trace points directly to this line.",
         "test": "tests/test_incident_scenarios.py::test_null_pointer_fixed"},
    ],
    "race_condition": [
        {"file": "services/checkout/concurrency.py", "pattern": r"current\s*=\s*_inventory\.get",
         "reason": "Unlocked read-modify-write lets concurrent checkouts double-deduct (lost update).",
         "test": "tests/test_incident_scenarios.py::test_race_condition_fixed"},
    ],
    "slow_query": [
        {"file": "services/checkout/queries.py", "pattern": r"for\s+\w+\s+in\s+ORDERS_TABLE",
         "reason": "Full-table scan on orders without an index key regresses p95 latency.",
         "test": "tests/test_incident_scenarios.py::test_slow_query_fixed"},
    ],
    "malformed_payload": [
        {"file": "services/checkout/validators.py", "pattern": r"amount_cents.*must be positive",
         "reason": "Strict schema validation rejects upstream carts with non-positive amounts.",
         "test": "tests/test_incident_scenarios.py::test_null_pointer_fixed"},
    ],
    "dependency_version_regression": [
        {"file": "requirements.txt", "pattern": r"(.+)",
         "reason": "Unpinned transitive dependency broke imports after deploy; pin markupsafe/jinja2.",
         "test": "tests/test_incident_scenarios.py::test_contract_mismatch_fixed"},
    ],
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
                    live_context: Optional[Dict[str, str]] = None,
                    stack_text: str = "", service: str = "",
                    service_mappings: Optional[Dict[str, str]] = None,
                    repo_available: bool = True) -> CodeInvestigation:
        """Deterministic investigation with stack-trace-first targeting.

        Never hallucinates: if the repo is unavailable -> unavailable reason;
        if nothing maps -> honest no-match (confidence limited by caller).
        """
        from tools.stacktrace import extract_stack_trace, primary_suspect
        from tools.code_search import search_code
        root = repo_root()
        if not repo_available or not os.path.isdir(root):
            return CodeInvestigation(
                incident_id=incident_id, root_cause_category=root_cause_category,
                findings=[],
                no_fix_reason=("No repository is connected to this project. RCA can identify "
                               "the likely application failure, but source-code-level findings "
                               "and automated patches are unavailable."))
        live_context = live_context or {}
        stack_text = stack_text or live_context.get("stack_trace", "")
        service = service or live_context.get("service", "")
        parsed = extract_stack_trace(stack_text) if stack_text else {"frames": []}
        suspect = primary_suspect(parsed) if parsed.get("frames") else None
        # 1) stack-trace-targeted search first (exact file+line wins)
        if suspect:
            try:
                res = search_code(root, service=service,
                                  service_mappings=service_mappings,
                                  stack=parsed,
                                  error_signature=live_context.get("error_signature", ""))
            except Exception:
                res = {"strategy": "no_match", "hits": []}
            if res.get("hits"):
                findings = [CodeFinding(
                    file=hit["file"], start_line=hit.get("line", 0) or 0,
                    end_line=hit.get("line", 0) or 0,
                    snippet=hit.get("snippet", "")[:400],
                    reason=(f"Stack trace points to {hit['file']}:{hit.get('line')} "
                            f"({hit.get('function') or 'unknown frame'})."),
                    related_test=None) for hit in res["hits"][:1]]
                return CodeInvestigation(incident_id=incident_id,
                                         root_cause_category=root_cause_category,
                                         findings=findings)
        # 2) category hunts (exact pattern search, no invention)
        hunts = HUNTS.get(root_cause_category, [])
        findings: List[CodeFinding] = []
        for hunt in hunts:
            path = os.path.join(root, hunt["file"])
            if not os.path.exists(path):
                continue
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()
            for i, line in enumerate(lines, start=1):
                m = re.search(hunt["pattern"], line.strip() or line)
                if m:
                    findings.append(CodeFinding(
                        file=hunt["file"], start_line=i, end_line=i,
                        snippet=line.rstrip(),
                        reason=hunt["reason"],
                        current_value=m.group(1) if m.groups() else None,
                        related_test=hunt["test"],
                    ))
        if not findings:
            if suspect:
                return CodeInvestigation(
                    incident_id=incident_id, root_cause_category=root_cause_category,
                    findings=[],
                    no_fix_reason=("We found an application-level error, but could not reliably "
                                   "map the stack trace to the connected repository."))
            return CodeInvestigation(
                incident_id=incident_id, root_cause_category=root_cause_category,
                findings=[],
                no_fix_reason=NO_FIX.get(root_cause_category,
                    "No safe code-level remediation identified."),
            )
        return CodeInvestigation(incident_id=incident_id,
                                 root_cause_category=root_cause_category,
                                 findings=findings)

    def recent_change(self, repo: str = "") -> Dict[str, str]:
        """Read-only recent-commit hint. Never blames recency alone."""
        import subprocess
        root = repo or repo_root()
        try:
            out = subprocess.run(
                ["git", "log", "--oneline", "-3", "--format=%h %s"],
                cwd=root, capture_output=True, text=True, timeout=5)
            lines = (out.stdout or "").strip().splitlines()
            if lines:
                return {"recent_commit": lines[0][:120],
                        "note": "Correlate with stack trace before attributing cause."}
        except Exception:
            pass
        return {"recent_commit": "", "note": "No git history available."}
