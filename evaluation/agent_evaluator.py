"""
Agent Evaluator - per-agent quality checks for Phase 3.
"""
import json
import os
from typing import Dict, Any, List

class AgentEvaluator:
    """Evaluates individual agent findings vs ground truth."""

    def evaluate_log_agent(self, findings: List, expected_codes: List[str]) -> Dict[str, Any]:
        found_codes = set()
        for f in findings:
            found_codes.update(f.related_error_codes)
        precision = len(set(expected_codes) & found_codes) / len(found_codes) if found_codes else 0
        recall = len(set(expected_codes) & found_codes) / len(expected_codes) if expected_codes else 1
        return {"precision": round(precision,3), "recall": round(recall,3), "found_codes": list(found_codes)}

    def evaluate_metrics_agent(self, findings: List, expected_severity: str) -> Dict[str, Any]:
        # Check that agent produced statement with 5xx and CPU observation
        has_5xx = any("5xx" in f.summary or "error rate" in f.summary.lower() for f in findings)
        has_cpu = any("cpu" in f.summary.lower() for f in findings)
        return {"has_5xx_observation": has_5xx, "has_cpu_observation": has_cpu, "findings_count": len(findings)}

    def evaluate_deployment_agent(self, findings: List) -> Dict[str, Any]:
        has_temporal = any("minutes before incident" in f.summary for f in findings)
        no_causation = all("caused" not in f.summary.lower() or "not proof" in f.summary.lower() for f in findings)
        return {"temporal_reported": has_temporal, "no_causation_claim": no_causation}

    def evaluate_knowledge_agent(self, findings: List) -> Dict[str, Any]:
        has_source = all(f.source_id and f.source_type for f in findings) if findings else True
        # Check that no invented source (must exist on disk)
        from pathlib import Path
        kb_root = Path(__file__).parent.parent / "knowledge"
        all_exist = True
        for f in findings:
            if not (kb_root / f.source_id).exists():
                all_exist = False
        return {"has_source_attribution": has_source, "all_sources_exist": all_exist, "count": len(findings)}
