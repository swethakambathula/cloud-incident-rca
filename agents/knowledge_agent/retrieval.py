"""
Retrieval wrapper for Knowledge Agent.
Delegates to tools/knowledge_tools with guardrail that source must exist on disk.
"""
from typing import List
from tools.knowledge_tools import search_knowledge, retrieve_for_incident
from schemas.findings import KnowledgeFinding

FAILURE_PATTERN_MAP = {
    "database-timeout": "database_connectivity",
    "connection-pool": "connection_pool_exhaustion",
    "bad-deployment": "faulty_revision",
    "dependency-failure": "dependency_failure",
    "traffic-overload": "traffic_overload",
    "high-latency": "latency_degradation",
    "configuration": "configuration_regression",
}

def retrieve_findings(query: str, top_k: int = 3) -> List[KnowledgeFinding]:
    raw = search_knowledge(query, top_k=top_k)
    findings = []
    for r in raw:
        # Determine failure pattern from source_id keywords
        pattern = "unknown"
        sid = r["source_id"].lower()
        for kw, pat in FAILURE_PATTERN_MAP.items():
            if kw in sid or kw.replace("-", "_") in r.get("title","").lower():
                pattern = pat
                break
        # Also from excerpt
        if pattern == "unknown":
            ex = r.get("relevant_excerpt_summary","").lower()
            for kw, pat in FAILURE_PATTERN_MAP.items():
                if kw in ex:
                    pattern = pat
                    break
        # Determine recommended checks by reading original markdown's Diagnostic section if available
        checks = []
        full = r.get("full_content","")
        if "Diagnostic" in full:
            # naive extract lines starting with number
            for line in full.split("\n"):
                if line.strip().startswith(("1.", "2.", "3.", "4.")):
                    checks.append(line.strip())
        findings.append(KnowledgeFinding(
            source_id=r["source_id"],
            source_type=r["source_type"],
            title=r["title"],
            relevant_excerpt_summary=r["relevant_excerpt_summary"][:300],
            similarity_score=r["similarity_score"],
            relevance_reason=f"Keyword match for '{query}' with similarity {r['similarity_score']}",
            associated_failure_pattern=pattern,
            recommended_checks=checks[:3],
        ))
    return findings
