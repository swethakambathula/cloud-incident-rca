"""
Patch Agent (Part 7): minimal deterministic diffs with SHA256 binding.

Each fixable category has an exact old->new replacement table. Generation
fails loudly if the expected faulty text is absent (patch would not apply
cleanly) instead of inventing a diff. Approval is bound to patch_sha256.
"""
import difflib
import hashlib
import os
from typing import Dict, List, Optional
from schemas.code_fix import PatchProposal
from agents.code_investigation_agent.agent import repo_root

# category -> replacements + metadata. Minimal diffs only.
PATCHES: Dict[str, Dict] = {
    "connection_pool_exhaustion": {
        "file": "services/checkout/database.py",
        "replacements": [("POOL_SIZE = 2", "POOL_SIZE = 20"),
                         ("POOL_TIMEOUT = 1", "POOL_TIMEOUT = 10")],
        "summary": "Raise checkout DB pool capacity 2->20 and acquire timeout 1s->10s",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_pool_exhaustion_fixed",
                  "tests/test_checkout.py::test_pool_sized_for_concurrency",
                  "tests/test_checkout.py::test_pool_timeout_allows_slow_queries"],
        "reasoning": "Pool usage hit 100% with healthy DB/CPU: bottleneck is client-side pool sizing, not the database.",
        "side_effects": "Up to 20 DB connections per instance; verify against DB max_connections.",
    },
    "faulty_revision": {
        "file": "services/checkout/config.py",
        "replacements": [("FEATURE_FLAG_NEW_BILLING = True", "FEATURE_FLAG_NEW_BILLING = False")],
        "summary": "Disable broken new-billing path (restore previous-revision behavior)",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_bad_deployment_fixed",
                  "tests/test_checkout.py::test_checkout_totals_cart"],
        "reasoning": "Errors began only on the new revision via the flagged code path; flag-off restores the healthy path.",
        "side_effects": "New billing features stay off until the underlying KeyError is fixed forward.",
    },
    "configuration_regression": {
        "file": "services/checkout/config.py",
        "replacements": [
            ('PAYMENT_GATEWAY_HOST = "payments.invalid"',
             'PAYMENT_GATEWAY_HOST = os.getenv("PAYMENT_GATEWAY_HOST", "payments.internal")'),
            ('PAYMENT_GATEWAY_API_KEY = ""',
             'PAYMENT_GATEWAY_API_KEY = os.getenv("PAYMENT_GATEWAY_API_KEY", "")'),
        ],
        "summary": "Read gateway host/key from environment with safe defaults",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_config_regression_fixed"],
        "reasoning": "Failure isolated to config-dependent endpoints; hardcoded values ignore the environment.",
        "side_effects": "Requires PAYMENT_GATEWAY_API_KEY to be set in the environment (fail-fast validate() preserved).",
    },
    "dependency_failure": {
        "file": "services/checkout/dependencies.py",
        "replacements": [("ORDERS_TIMEOUT_S = 1", "ORDERS_TIMEOUT_S = 5"),
                         ("ORDERS_MAX_RETRIES = 0", "ORDERS_MAX_RETRIES = 2")],
        "summary": "Downstream timeout 1s->5s with 2 retries for transient slowness",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_dependency_timeout_fixed"],
        "reasoning": "Checkout 500s track orders p99 slowness; 1s timeout with zero retries converts transient slowness into hard failures.",
        "side_effects": "Slightly higher tail latency on slow downstream calls; add circuit breaker as follow-up.",
    },
    "null_pointer": {
        "file": "services/checkout/payment_processor.py",
        "replacements": [("    # --- FAULT: None dereference when payment_profile is None ---\n    amount = payment_profile.amount",
                          "    if payment_profile is None:\n        raise PaymentProfileNotFound(\n            f\"no payment profile for user {user_id}\")\n    amount = payment_profile.amount")],
        "summary": "Guard None payment_profile with PaymentProfileNotFound before attribute access",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_null_pointer_fixed"],
        "reasoning": "Prevents NoneType failure observed in incident logs; guest checkout has no stored profile.",
        "side_effects": "Guests now get a typed 404-style error instead of a 500; add guest-checkout flow as follow-up.",
    },
    "contract_mismatch": {
        "file": "services/orders/contract.py",
        "replacements": [('    payload["total"] = Decimal("19.99")',
                          '    payload["total"] = str(Decimal("19.99"))')],
        "summary": "Serialize Decimal totals as strings for JSON contract compatibility",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_contract_mismatch_fixed"],
        "reasoning": "Orders response schema leaks Decimal into json.dumps; stringify at the boundary.",
        "side_effects": "Consumers must parse numeric strings; add contract versioning as follow-up.",
    },
    "race_condition": {
        "file": "services/checkout/concurrency.py",
        "replacements": [("def deduct_inventory(sku: str, qty: int, use_lock: bool = False):",
                          "def deduct_inventory(sku: str, qty: int, use_lock: bool = True):")],
        "summary": "Default inventory deduction to locked path (atomic update)",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_race_condition_fixed"],
        "reasoning": "Eliminates lost-update oversell under concurrent checkout.",
        "side_effects": "Marginal lock contention under extreme concurrency; monitor.",
    },
    "slow_query": {
        "file": "services/checkout/queries.py",
        "replacements": [("    # --- FAULT: full scan instead of indexed lookup ---\n    return [o for o in ORDERS_TABLE if o[\"user_id\"] == user_id]",
                          "    # indexed lookup by user_id (fix: avoid full-table scan)\n    _INDEX = {}\n    for o in ORDERS_TABLE:\n        _INDEX.setdefault(o[\"user_id\"], []).append(o)\n    return list(_INDEX.get(user_id, []))")],
        "summary": "Replace full-table scan with indexed lookup by user_id",
        "risk": "LOW",
        "tests": ["tests/test_incident_scenarios.py::test_slow_query_fixed"],
        "reasoning": "Removes seq-scan p95 regression on order_history.",
        "side_effects": "Index built per call in demo; production should use a DB index.",
    },
}


class PatchAgent:
    agent_name = "Patch Agent"

    def generate(self, incident_id: str, root_cause_category: str,
                   preferred_file: str = "") -> Optional[PatchProposal]:
        spec = PATCHES.get(root_cause_category)
        # Prefer the patch that matches the blamed code finding's file so the
        # fix addresses the investigated location, not just the category.
        if preferred_file:
            for key, cand in PATCHES.items():
                if cand.get("file") == preferred_file:
                    spec = cand
                    break
        if not spec:
            return None
        path = os.path.join(repo_root(), spec["file"])
        with open(path, encoding="utf-8") as f:
            original = f.read()
        patched = original
        for old, new in spec["replacements"]:
            if old not in patched:
                raise ValueError(
                    f"Patch does not apply cleanly: expected faulty text {old!r} "
                    f"absent from {spec['file']} (already fixed or diverged?)")
            patched = patched.replace(old, new, 1)
        diff = "".join(difflib.unified_diff(
            original.splitlines(keepends=True), patched.splitlines(keepends=True),
            fromfile=f"a/{spec['file']}", tofile=f"b/{spec['file']}"))
        # git apply rejects space-only context lines from difflib: strip them
        diff = "\n".join("" if line == " " else line for line in diff.split("\n"))
        sha = hashlib.sha256(diff.encode()).hexdigest()
        added = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
        removed = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
        return PatchProposal(
            incident_id=incident_id, root_cause_category=root_cause_category,
            files_changed=[spec["file"]], summary=spec["summary"], risk=spec["risk"],
            patch=diff, tests_to_run=spec["tests"],
            reasoning_summary=spec["reasoning"] + " Side effects: " + spec["side_effects"],
            patch_sha256=sha, lines_added=added, lines_removed=removed,
        )
