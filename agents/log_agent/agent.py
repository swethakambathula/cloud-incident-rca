"""
Log Investigation Agent - analyzes Cloud Logging evidence.
Tool Guardrail: may only read evidence.application_errors, evidence.request_errors, evidence.raw_evidence, evidence.traces - NOT metrics or deployment APIs.
"""
import logging
from typing import List
from collections import Counter
from datetime import datetime

from schemas.evidence import IncidentEvidence
from schemas.findings import AgentFinding, FindingType, EvidenceStrength

logger = logging.getLogger("log_agent")

# Allowed tool markers (for guardrail verification)
ALLOWED_EVIDENCE_FIELDS = {"application_errors", "request_errors", "raw_evidence", "traces", "symptoms"}


class LogInvestigationAgent:
    agent_name = "Log Investigation Agent"

    def investigate(self, evidence: IncidentEvidence) -> List[AgentFinding]:
        findings: List[AgentFinding] = []

        # Guardrail check (we only access allowed fields)
        # Analyze application errors
        app_errors = evidence.application_errors or []
        req_errors = evidence.request_errors or []
        raw = evidence.raw_evidence or []

        if not app_errors and not req_errors:
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.ERROR_PATTERN,
                evidence_strength=EvidenceStrength.MISSING_EVIDENCE,
                summary="No application or request error logs present in incident window",
                supporting_evidence=[],
                confidence=0.4,
                missing_information=["Application error logs unavailable - requires broader time window or log filter check"],
            ))
            return findings

        # Dominant error pattern
        counter = Counter()
        for e in app_errors:
            code = e.get("error_code") if isinstance(e, dict) else str(e)
            counter[code] += e.get("count", 1) if isinstance(e, dict) and "count" in e else 1

        if counter:
            dominant, cnt = counter.most_common(1)[0]
            total = sum(counter.values())
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.ERROR_PATTERN,
                evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                summary=f"Dominant error pattern: {dominant} occurred {cnt} times ({cnt/total*100:.1f}% of application errors)",
                supporting_evidence=[f"{code}: {c} occurrences" for code, c in counter.most_common()],
                confidence=0.92,
                affected_service=evidence.service_name,
                related_error_codes=list(counter.keys()),
                timestamp_range={"start": evidence.start_time, "end": evidence.end_time},
            ))

        # Group repeated errors & first occurrence
        if raw:
            # Find earliest error timestamp
            timestamps = [r.get("timestamp") for r in raw if r.get("timestamp")]
            timestamps_sorted = sorted(timestamps) if timestamps else []
            if timestamps_sorted:
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.ERROR_PATTERN,
                    evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                    summary=f"First error occurrence at {timestamps_sorted[0]}; error spike spans {evidence.start_time} to {evidence.end_time}",
                    supporting_evidence=timestamps_sorted[:3],
                    confidence=0.85,
                    timestamp_range={"start": timestamps_sorted[0], "end": timestamps_sorted[-1]} if len(timestamps_sorted) > 1 else {"start": timestamps_sorted[0], "end": evidence.end_time},
                ))

        # Affected endpoints
        endpoints = set()
        for r in req_errors:
            ep = r.get("endpoint") if isinstance(r, dict) else None
            if ep:
                endpoints.add(ep)
        for e in app_errors:
            ep = e.get("endpoint") if isinstance(e, dict) else None
            if ep:
                endpoints.add(ep)
        if endpoints:
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.ERROR_PATTERN,
                evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                summary=f"Affected endpoints: {', '.join(sorted(endpoints))}",
                supporting_evidence=[f"Endpoint {ep} returned errors" for ep in sorted(endpoints)],
                confidence=0.88,
                affected_service=evidence.service_name,
                affected_endpoint=list(endpoints)[0] if endpoints else None,
            ))

        # Dependencies mentioned
        deps = evidence.dependencies or []
        dep_names = [d.get("name") for d in deps if d.get("name")]
        if dep_names:
            for dep in deps:
                status = dep.get("status", "UNKNOWN")
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.GENERAL,
                    evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                    summary=f"Dependency {dep.get('name')} status: {status}",
                    supporting_evidence=[f"Dependency {dep.get('name')} reported status {status}"],
                    confidence=0.80,
                    affected_service=dep.get("name"),
                ))

        # Distinguish warning vs error vs critical from severity or error code
        warning_like = [c for c in counter if "WARNING" in c or "WARN" in c] if counter else []
        critical_like = [c for c in counter if "CRITICAL" in c or "TIMEOUT" in c or "EXHAUSTED" in c]
        if warning_like:
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.GENERAL,
                evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                summary=f"Warning-level signals detected: {', '.join(warning_like)}",
                supporting_evidence=warning_like,
                confidence=0.65,
            ))

        # Error frequency change observation
        if app_errors:
            total_errors = sum(e.get("count", 1) for e in app_errors if isinstance(e, dict))
            if total_errors > 100:
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.ERROR_PATTERN,
                    evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                    summary=f"High error frequency: {total_errors} errors in window indicates systemic failure, not transient",
                    supporting_evidence=[f"Total application errors: {total_errors}"],
                    confidence=0.90,
                ))

        # Check for missing information
        if not evidence.traces:
            findings[-1].missing_information.append("Trace correlation unavailable - cross-service propagation cannot be confirmed via logs alone") if findings else None

        return findings
