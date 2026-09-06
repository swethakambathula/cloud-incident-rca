"""
Knowledge / RAG Agent - retrieves runbooks, architecture, historical incidents with source attribution.
Guardrail: only knowledge_tools allowed. Returns source_id for every claim.
"""
from typing import List
from schemas.evidence import IncidentEvidence
from schemas.findings import KnowledgeFinding
from .retrieval import retrieve_findings
from tools.knowledge_tools import retrieve_for_incident

class KnowledgeAgent:
    agent_name = "Knowledge / RAG Agent"

    def investigate(self, evidence: IncidentEvidence) -> List[KnowledgeFinding]:
        # Build queries from evidence signals
        # Primary error code
        error_codes = [e.get("error_code","") for e in evidence.application_errors if isinstance(e, dict)]
        queries = []
        if error_codes:
            queries.append(" ".join(error_codes))
        if evidence.symptoms:
            queries.append(" ".join(evidence.symptoms[:2]))
        # Deployment query
        if evidence.recent_deployments:
            queries.append("bad deployment revision NullPointer traffic")
        deps = [d.get("name","") for d in evidence.dependencies if d.get("status") != "HEALTHY"]
        if deps:
            queries.append("dependency failure " + " ".join(deps))
        # Fallback
        if not queries:
            queries.append("incident")

        all_findings: List[KnowledgeFinding] = []
        seen = set()
        for q in queries[:3]:
            kfs = retrieve_findings(q, top_k=2)
            for kf in kfs:
                if kf.source_id not in seen:
                    seen.add(kf.source_id)
                    all_findings.append(kf)
        # If still empty, try generic retrieve_for_incident
        if not all_findings:
            raw = retrieve_for_incident(evidence)
            for r in raw[:3]:
                # manual map
                from .retrieval import FAILURE_PATTERN_MAP
                pattern = "unknown"
                sid = r["source_id"].lower()
                for kw, pat in FAILURE_PATTERN_MAP.items():
                    if kw in sid:
                        pattern = pat
                        break
                all_findings.append(KnowledgeFinding(
                    source_id=r["source_id"],
                    source_type=r["source_type"],
                    title=r["title"],
                    relevant_excerpt_summary=r["relevant_excerpt_summary"][:300],
                    similarity_score=r["similarity_score"],
                    relevance_reason=f"Similarity to incident symptoms/error codes",
                    associated_failure_pattern=pattern,
                    recommended_checks=[],
                ))
        # Filter irrelevant: require similarity >0.1
        filtered = [f for f in all_findings if f.similarity_score > 0.1]
        # Preserve attribution; never hallucinate source_id not on disk
        # Already guaranteed by retrieval reading disk.
        return filtered[:5]
