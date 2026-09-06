"""
Knowledge / RAG Tools.
Provides keyword-based retrieval over local knowledge base (runbooks, architecture, historical incidents)
with source attribution. No LLM invents historical incidents.
"""
import os
import re
from typing import List, Dict, Any
from pathlib import Path

KNOWLEDGE_ROOT = Path(__file__).parent.parent / "knowledge"

# Allowed source types
SOURCE_TYPE_MAP = {
    "runbooks": "runbook",
    "architecture": "architecture",
    "historical_incidents": "historical_incident",
}

FAILURE_PATTERN_KEYWORDS = {
    "database_connectivity": ["database", "timeout", "connection", "vpc", "cloud sql"],
    "connection_pool_exhaustion": ["pool", "exhaust", "saturation", "waiting_threads", "connection pool"],
    "faulty_revision": ["deployment", "revision", "null_pointer", "NullPointer", "rollback", "revision"],
    "dependency_failure": ["dependency", "downstream", "orders-service", "unavailable", "cascade"],
    "traffic_overload": ["traffic", "overload", "capacity", "cpu", "throttled", "request volume"],
    "configuration_regression": ["config", "environment", "secret", "misconfigured"],
    "latency_degradation": ["latency", "p95", "p99", "slow", "queue"],
}


def _read_docs() -> List[Dict[str, Any]]:
    docs = []
    for subdir in ["runbooks", "architecture", "historical_incidents"]:
        dir_path = KNOWLEDGE_ROOT / subdir
        if not dir_path.exists():
            continue
        for fp in dir_path.glob("*.md"):
            try:
                text = fp.read_text(encoding="utf-8")
            except Exception:
                continue
            title = text.split("\n")[0].replace("#", "").strip() if text else fp.stem
            docs.append({
                "source_id": f"{subdir}/{fp.name}",
                "source_type": SOURCE_TYPE_MAP.get(subdir, subdir),
                "title": title,
                "content": text,
                "path": str(fp),
            })
    return docs


def _score_doc(query_keywords: List[str], doc_content: str) -> float:
    content_lower = doc_content.lower()
    hits = sum(1 for kw in query_keywords if kw.lower() in content_lower)
    if not query_keywords:
        return 0.0
    base = hits / len(query_keywords)
    # Bonus if mentions multiple distinct keywords
    bonus = min(0.2, hits * 0.05)
    return min(1.0, base + bonus)


def search_knowledge(
    query: str,
    top_k: int = 3,
    source_filter: List[str] = None
) -> List[Dict[str, Any]]:
    """
    Keyword search over knowledge base with source attribution.
    Returns list of dicts with source_id, source_type, title, excerpt, similarity_score.
    """
    docs = _read_docs()
    if source_filter:
        docs = [d for d in docs if d["source_type"] in source_filter]
    # Tokenize query
    keywords = re.findall(r"[a-zA-Z0-9_-]+", query.lower())
    # Also expand with failure pattern synonyms if query maps to known pattern
    for pattern, syns in FAILURE_PATTERN_KEYWORDS.items():
        if pattern.lower() in query.lower():
            keywords.extend(syns)
    keywords = list(set(keywords))
    scored = []
    for d in docs:
        score = _score_doc(keywords, d["content"])
        if score > 0:
            # Extract excerpt: first 400 chars around first keyword hit
            lower = d["content"].lower()
            first_idx = len(d["content"])
            for kw in keywords:
                idx = lower.find(kw.lower())
                if idx != -1 and idx < first_idx:
                    first_idx = idx
            start = max(0, first_idx - 100)
            excerpt = d["content"][start:start + 400].strip()
            scored.append({
                "source_id": d["source_id"],
                "source_type": d["source_type"],
                "title": d["title"],
                "relevant_excerpt_summary": excerpt[:380].replace("\n", " "),
                "similarity_score": round(score, 3),
                "full_content": d["content"],
            })
    scored.sort(key=lambda x: x["similarity_score"], reverse=True)
    return scored[:top_k]


def retrieve_for_incident(evidence) -> List[Dict[str, Any]]:
    """
    Helper to build a query from IncidentEvidence and retrieve relevant docs.
    """
    parts = []
    # Collect error codes
    for e in getattr(evidence, "application_errors", []):
        if isinstance(e, dict):
            parts.append(e.get("error_code", ""))
    parts.extend(getattr(evidence, "symptoms", [])[:2])
    # Latency / cpu hints
    lat = getattr(evidence, "latency", {}) or {}
    if lat.get("severity") == "CRITICAL":
        parts.append("high latency")
    # Deployment hint
    if getattr(evidence, "recent_deployments", []):
        parts.append("deployment revision")
    deps = getattr(evidence, "dependencies", []) or []
    for d in deps:
        if d.get("status") != "HEALTHY":
            parts.append("dependency failure " + d.get("name", ""))
    query = " ".join(filter(None, parts)) or "incident"
    return search_knowledge(query, top_k=5)
