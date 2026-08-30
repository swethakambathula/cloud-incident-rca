"""
Evidence Extractor Tool for Cloud Incident RCA Agent.
Analyzes parsed log entries to extract relevant evidence items, rank error signatures, and construct causal timelines.
"""
import re
from typing import List, Dict, Any, Tuple
from agents.rca_agent.schemas import LogEntry, LogLevel, EvidenceItem, TimelineEvent, IncidentContext


class EvidenceExtractor:
    """Extracts evidence snippets, identifies anomalies, and ranks candidate root causes."""

    ROOT_CAUSE_PATTERNS = [
        (r'ConnectionPoolTimeout|pool exhausted|MaxConnectionsReached|connection timeout', 'DATABASE_POOL_EXHAUSTION', 0.95),
        (r'OutOfMemoryError|OOMKilled|Memory limit exceeded|MemoryLeak', 'MEMORY_EXHAUSTION', 0.95),
        (r'504 Gateway Timeout|upstream connect error|502 Bad Gateway', 'INGRESS_GATEWAY_TIMEOUT', 0.85),
        (r'DeadlockDetected|Lock wait timeout exceeded', 'DATABASE_DEADLOCK', 0.90),
        (r'RateLimitExceeded|429 Too Many Requests|quota exceeded', 'RATE_LIMIT_EXCEEDED', 0.85),
        (r'DNS resolve failed|Name or service not known|NXDOMAIN', 'DNS_RESOLUTION_FAILURE', 0.85),
        (r'SSLHandshakeException|Certificate expired|TLS handshake timeout', 'SECURITY_TLS_FAILURE', 0.80),
    ]

    @classmethod
    def extract_evidence(cls, entries: List[LogEntry], context: IncidentContext) -> List[EvidenceItem]:
        """Extracts high-relevance evidence items from log entries."""
        evidence_list: List[EvidenceItem] = []

        # Sort log entries chronologically
        sorted_entries = sorted(
            entries,
            key=lambda x: x.parsed_timestamp if x.parsed_timestamp else x.timestamp
        )

        for idx, entry in enumerate(sorted_entries):
            # Check for error/critical anomalies
            if entry.level in (LogLevel.ERROR, LogLevel.CRITICAL, LogLevel.FATAL):
                relevance = 0.70

                # Check pattern matches for high confidence root cause signatures
                matched_pattern_type = "ERROR_LOG"
                for pattern, p_type, confidence in cls.ROOT_CAUSE_PATTERNS:
                    if re.search(pattern, entry.message, re.IGNORECASE) or (entry.stack_trace and re.search(pattern, entry.stack_trace, re.IGNORECASE)):
                        matched_pattern_type = p_type
                        relevance = confidence
                        break

                # Boost relevance if entry is earliest error in service timeline
                if idx == 0 or not any(e.service == entry.service for e in sorted_entries[:idx]):
                    relevance += 0.05

                evidence = EvidenceItem(
                    id=f"EV-{len(evidence_list)+1:03d}",
                    timestamp=entry.timestamp,
                    source_service=entry.service,
                    type=matched_pattern_type,
                    description=entry.message[:200],
                    raw_excerpt=entry.stack_trace or entry.raw_log,
                    relevance_score=min(1.0, relevance),
                    metadata=entry.metadata
                )
                evidence_list.append(evidence)

        # Sort evidence by relevance score descending
        evidence_list.sort(key=lambda e: e.relevance_score, reverse=True)
        return evidence_list

    @classmethod
    def build_timeline(cls, entries: List[LogEntry]) -> List[TimelineEvent]:
        """Synthesizes chronological timeline events from logs."""
        sorted_entries = sorted(
            entries,
            key=lambda x: x.parsed_timestamp if x.parsed_timestamp else x.timestamp
        )
        timeline: List[TimelineEvent] = []

        for idx, entry in enumerate(sorted_entries):
            is_candidate = False
            event_type = f"LOG_{entry.level.value}"

            for pattern, p_type, _ in cls.ROOT_CAUSE_PATTERNS:
                if re.search(pattern, entry.message, re.IGNORECASE) or (entry.stack_trace and re.search(pattern, entry.stack_trace, re.IGNORECASE)):
                    event_type = p_type
                    is_candidate = True
                    break

            timeline.append(
                TimelineEvent(
                    timestamp=entry.timestamp,
                    service=entry.service,
                    event_type=event_type,
                    summary=entry.message[:150],
                    is_root_cause_candidate=is_candidate,
                    details={"level": entry.level.value, "has_stack_trace": bool(entry.stack_trace)}
                )
            )

        return timeline
