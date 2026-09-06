"""
Evidence Aggregation - combines findings from specialized agents, deduplicates,
preserves source, detects conflicts, classifies strength.
"""
from typing import List, Dict
from collections import defaultdict
from schemas.findings import AgentFinding, KnowledgeFinding, EvidenceStrength
from schemas.evidence import IncidentEvidence

class EvidenceAggregator:
    """
    Aggregator combines log, metrics, deployment, trace, knowledge findings.
    Categories:
      DIRECT_EVIDENCE, CORRELATED_EVIDENCE, HISTORICAL_EVIDENCE,
      CONTRADICTORY_EVIDENCE, MISSING_EVIDENCE
    """

    def aggregate(self, findings: List[AgentFinding], knowledge: List[KnowledgeFinding]) -> Dict[str, List]:
        """
        Returns dict mapping EvidenceStrength -> list of findings/strings.
        Also detects conflicting findings.
        """
        buckets: Dict[str, List] = defaultdict(list)
        for f in findings:
            key = f.evidence_strength.value if isinstance(f.evidence_strength, EvidenceStrength) else str(f.evidence_strength)
            buckets[key].append(f)
        for k in knowledge:
            buckets[EvidenceStrength.HISTORICAL_EVIDENCE.value].append(k)

        # Detect conflicting findings: e.g., one says DB unhealthy, another says healthy; or CPU critical vs normal
        conflicts = []
        # Group by semantic: deployment vs dependency origin etc.
        dep_statuses = set()
        cpu_states = set()
        for f in findings:
            summ = f.summary.lower()
            if "cpu" in summ:
                if "normal" in summ:
                    cpu_states.add("NORMAL")
                if "critical" in summ:
                    cpu_states.add("CRITICAL")
            if "dependency" in summ or "downstream" in summ:
                if "healthy" in summ:
                    dep_statuses.add("HEALTHY")
                if "unavailable" in summ or "unreachable" in summ:
                    dep_statuses.add("UNAVAILABLE")
        if len(cpu_states) > 1:
            conflicts.append(f"Conflicting CPU assessments: {cpu_states} - metrics agent vs log inference")
        if len(dep_statuses) > 1:
            conflicts.append(f"Conflicting dependency health: {dep_statuses} - trace vs metrics evidence")

        buckets["CONTRADICTORY_EVIDENCE_DETECTED"] = conflicts

        # Deduplicate: same summary from multiple agents
        seen = set()
        deduped_findings = []
        for f in findings:
            key = f.summary[:100]
            if key not in seen:
                seen.add(key)
                deduped_findings.append(f)
        buckets["DEDUPED_FINDINGS"] = deduped_findings

        # Separate observations vs interpretations
        observations = [f for f in deduped_findings if f.evidence_strength in (EvidenceStrength.DIRECT_EVIDENCE, EvidenceStrength.CORRELATED_EVIDENCE)]
        interpretations = [f for f in deduped_findings if "should" in f.summary.lower() or "likely" in f.summary.lower()]
        buckets["OBSERVATIONS"] = observations
        buckets["INTERPRETATIONS"] = interpretations

        return dict(buckets)

    def classify_evidence_strength(self, evidence: IncidentEvidence, findings: List[AgentFinding]) -> Dict[str, float]:
        """
        Returns quality score per strength for confidence recalibration.
        """
        counts = defaultdict(int)
        for f in findings:
            counts[f.evidence_strength.value] += 1
        total = len(findings) or 1
        return {k: v/total for k,v in counts.items()}
