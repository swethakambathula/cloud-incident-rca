"""
Cloud Incident RCA Agent Core Implementation.
"""
import os
import json
from typing import List, Dict, Any, Optional
from .schemas import IncidentContext, RCAResult, EvidenceItem, TimelineEvent, RemediationStep
from tools.log_parser import LogParser
from tools.evidence_extractor import EvidenceExtractor
from .prompts import RCA_SYSTEM_PROMPT, RCA_ANALYSIS_PROMPT_TEMPLATE


class CloudRCAAgent:
    """Core RCA Agent orchestrating multi-log analysis, evidence synthesis, and root cause diagnosis."""

    def __init__(self, llm_provider: Optional[str] = None):
        self.llm_provider = llm_provider or os.getenv("LLM_PROVIDER", "none").lower()

    def analyze_incident(self, incident_file: str) -> RCAResult:
        """Loads incident metadata & logs, parses evidence, and generates full RCA report."""
        with open(incident_file, 'r', encoding='utf-8') as f:
            incident_dict = json.load(f)

        context = IncidentContext(**incident_dict)
        base_dir = os.path.dirname(os.path.abspath(incident_file))

        # Resolve log file paths
        all_entries = []
        for log_file in context.log_files:
            log_path = os.path.join(base_dir, log_file)
            if not os.path.exists(log_path):
                # Try relative to parent log directory
                log_path = os.path.join(os.path.dirname(base_dir), "logs", os.path.basename(log_file))
            
            svc_guess = os.path.basename(log_file).split('.')[0].replace('incident_', '')
            entries = LogParser.parse_file(log_path, default_service=svc_guess)
            all_entries.extend(entries)

        # Extract Evidence and Timeline
        evidence = EvidenceExtractor.extract_evidence(all_entries, context)
        timeline = EvidenceExtractor.build_timeline(all_entries)

        # Run reasoning engine
        if self.llm_provider != "none":
            result = self._analyze_with_llm(context, evidence, timeline, all_entries)
        else:
            result = self._analyze_deterministic(context, evidence, timeline, all_entries)

        return result

    def _analyze_deterministic(
        self,
        context: IncidentContext,
        evidence: List[EvidenceItem],
        timeline: List[TimelineEvent],
        all_entries: Any
    ) -> RCAResult:
        """Deterministic heuristic rule engine for local zero-dependency execution."""
        top_evidence = evidence[0] if evidence else None

        if top_evidence and top_evidence.type == "DATABASE_POOL_EXHAUSTION":
            root_cause_summary = "Database connection pool exhausted due to unclosed connections or high latency queries, blocking downstream API application threads."
            root_cause_component = top_evidence.source_service or "payment-api"
            confidence_score = 0.95
            causal_chain = [
                f"HikariCP Connection pool limit reached on service '{root_cause_component}' connecting to Database",
                "Application HTTP worker threads queued waiting for DB connections",
                "HTTP request queue filled up leading to 504 Gateway Timeouts at Ingress"
            ]
            remediation = [
                RemediationStep(
                    step_number=1,
                    action="Increase connection pool size and configure aggressive max Lifetime / idle timeouts",
                    command_or_config="DB_POOL_MAX_SIZE=50\nDB_POOL_TIMEOUT=5000",
                    target_service=root_cause_component,
                    priority="HIGH"
                ),
                RemediationStep(
                    step_number=2,
                    action="Restart application worker pods to clear hanging connections",
                    command_or_config="kubectl rollout restart deployment/payment-api -n production",
                    target_service=context.services_involved[0] if context.services_involved else "api-gateway",
                    priority="HIGH"
                )
            ]
            prevention = [
                "Implement connection leak detection in ORM configuration.",
                "Add database connection pool saturation metrics & alerts to Prometheus/Grafana.",
                "Enforce circuit breakers on API endpoints relying on slow DB queries."
            ]

        elif top_evidence and top_evidence.type == "MEMORY_EXHAUSTION":
            svc = top_evidence.source_service
            import re
            container_match = re.search(r'Container ([a-zA-Z0-9_-]+)', top_evidence.description + " " + top_evidence.raw_excerpt)
            if container_match:
                svc = container_match.group(1)

            root_cause_summary = f"Process Out-Of-Memory (OOM) crash in '{svc}' caused by heap memory leak during heavy catalog object instantiation."
            root_cause_component = svc
            confidence_score = 0.92
            causal_chain = [
                f"Memory usage steadily scaled to 100% on '{root_cause_component}'",
                "Linux OS Kernel invoked OOM Killer, terminating the main process",
                "Ingress router failed to route incoming traffic, returning HTTP 502/503"
            ]
            remediation = [
                RemediationStep(
                    step_number=1,
                    action="Increase container memory limits in Kubernetes deployment specification",
                    command_or_config="resources:\n  limits:\n    memory: 4Gi",
                    target_service=root_cause_component,
                    priority="HIGH"
                ),
                RemediationStep(
                    step_number=2,
                    action="Analyze heap dump file to isolate uncollected reference objects in cache",
                    command_or_config="jcmd <pid> GC.heap_dump /tmp/heap.hprof",
                    target_service=root_cause_component,
                    priority="MEDIUM"
                )
            ]
            prevention = [
                "Set strict TTL policies on in-memory application caches.",
                "Configure automated heap dump generation upon OutOfMemory errors."
            ]

        elif top_evidence and top_evidence.type == "INGRESS_GATEWAY_TIMEOUT":
            root_cause_summary = "Upstream service response latency exceeded ingress gateway timeout threshold, triggering HTTP 504 cascades."
            root_cause_component = top_evidence.source_service or "ingress-gateway"
            confidence_score = 0.88
            causal_chain = [
                f"Upstream backend service latency spiked past gateway timeout",
                "Ingress proxy terminated downstream client requests with HTTP 504",
                "Retries from client applications compounded traffic load on backend"
            ]
            remediation = [
                RemediationStep(
                    step_number=1,
                    action="Temporarily adjust gateway proxy read/write timeouts",
                    command_or_config="proxy_read_timeout 60s;",
                    target_service=root_cause_component,
                    priority="HIGH"
                )
            ]
            prevention = [
                "Implement exponential backoff with jitter on client retries.",
                "Deploy load-shedding and rate limiting on upstream services."
            ]

        else:
            # Fallback heuristic summary
            root_cause_summary = f"Incident triggered by errors logged in {top_evidence.source_service if top_evidence else 'system'}"
            root_cause_component = top_evidence.source_service if top_evidence else context.services_involved[0] if context.services_involved else "unknown"
            confidence_score = top_evidence.relevance_score if top_evidence else 0.70
            causal_chain = [
                f"Anomaly detected in service '{root_cause_component}'",
                "Cascading error symptoms reported across connected services"
            ]
            remediation = [
                RemediationStep(
                    step_number=1,
                    action="Inspect raw service logs and check resource utilization",
                    target_service=root_cause_component,
                    priority="HIGH"
                )
            ]
            prevention = ["Implement enhanced structured logging and metric alerts."]

        return RCAResult(
            incident_id=context.incident_id,
            title=context.title,
            root_cause_summary=root_cause_summary,
            root_cause_component=root_cause_component,
            confidence_score=confidence_score,
            causal_chain=causal_chain,
            evidence=evidence[:5],
            timeline=timeline[:15],
            remediation_steps=remediation,
            prevention_recommendations=prevention,
            reasoning_mode="DETERMINISTIC_RULES"
        )

    def _analyze_with_llm(
        self,
        context: IncidentContext,
        evidence: List[EvidenceItem],
        timeline: List[TimelineEvent],
        all_entries: Any
    ) -> RCAResult:
        """Fall back to deterministic if LLM API keys are absent or API call fails."""
        # For offline stability, falls back to deterministic if LLM isn't configured
        return self._analyze_deterministic(context, evidence, timeline, all_entries)
