"""
Trace / Dependency Agent.
Guardrail: only trace_tools allowed (get_trace_id_from_log, get_related_trace_events).
Builds dependency path and distinguishes origin vs affected.
"""
from typing import List
from schemas.evidence import IncidentEvidence
from schemas.findings import AgentFinding, FindingType, EvidenceStrength


class TraceInvestigationAgent:
    agent_name = "Trace / Dependency Agent"
    ALLOWED_FIELDS = {"traces", "dependencies", "raw_evidence"}

    def investigate(self, evidence: IncidentEvidence) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        traces = evidence.traces or []
        deps = evidence.dependencies or []

        if not traces and not deps:
            findings.append(AgentFinding(
                agent_name=self.agent_name,
                finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                evidence_strength=EvidenceStrength.MISSING_EVIDENCE,
                summary="No trace IDs or dependency signals available - cannot reconstruct request path",
                supporting_evidence=[],
                confidence=0.45,
                missing_information=["Trace IDs and dependency health checks unavailable"],
                affected_service=evidence.service_name,
            ))
            return findings

        # Dependency impact
        for d in deps:
            name = d.get("name", "unknown")
            status = d.get("status", "UNKNOWN")
            if status in ("UNAVAILABLE", "UNREACHABLE", "ERROR"):
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                    summary=f"Dependency {name} status {status} - downstream failure detected; origin likely {name}, affected {evidence.service_name}",
                    supporting_evidence=[f"Dependency {name} status {status}", f"Trace path suggests failure originates in {name}"],
                    confidence=0.92,
                    affected_service=name,
                ))
                # Propagation observation
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                    summary=f"Failure propagation: Client -> {evidence.service_name} -> {name} (failing) -> HTTP 502/503 upstream",
                    supporting_evidence=[f"Path: Client -> {evidence.service_name} -> {name}"],
                    confidence=0.88,
                    affected_service=evidence.service_name,
                ))
            elif status == "HEALTHY":
                # Healthy downstream is contradictory for dependency hypothesis
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.CONTRADICTORY_EVIDENCE,
                    summary=f"Dependency {name} reports HEALTHY status with details {d}",
                    supporting_evidence=[f"Dependency {name} healthy: {d}"],
                    confidence=0.80,
                    affected_service=evidence.service_name,
                ))
                # Also detect if healthy but pool exhausted suggests client-side
                server_cpu = d.get("server_cpu_pct")
                if server_cpu is not None and server_cpu < 30:
                    findings.append(AgentFinding(
                        agent_name=self.agent_name,
                        finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                        evidence_strength=EvidenceStrength.CONTRADICTORY_EVIDENCE,
                        summary=f"Downstream DB server CPU {server_cpu}% normal - contradicts DB outage hypothesis, suggests client-side pool/config issue",
                        supporting_evidence=[f"DB CPU {server_cpu}% healthy"],
                        confidence=0.85,
                    ))

        # Trace path reconstruction
        for t in traces:
            tid = t.get("trace_id", "unknown")
            duration = t.get("duration_ms", t.get("db_span_duration_ms", 0))
            root_span = t.get("root_span", t.get("endpoint", "/unknown"))
            # Identify latency bottleneck
            queue_wait = t.get("queue_wait_ms")
            db_span = t.get("db_span_duration_ms") or t.get("db_query_ms")
            if queue_wait and db_span:
                if queue_wait > db_span * 10:
                    findings.append(AgentFinding(
                        agent_name=self.agent_name,
                        finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                        evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                        summary=f"Trace {tid} latency bottleneck: queue_wait {queue_wait}ms >> db_query {db_span}ms - indicates client pool exhaustion, not DB slowness",
                        supporting_evidence=[f"Trace {tid}: queue_wait {queue_wait}ms, db_query {db_span}ms, total {duration}ms"],
                        confidence=0.93,
                        affected_service=evidence.service_name,
                    ))
                elif db_span > 4000:
                    findings.append(AgentFinding(
                        agent_name=self.agent_name,
                        finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                        evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                        summary=f"Trace {tid} latency bottleneck: db_span {db_span}ms dominates total {duration}ms - indicates database timeout",
                        supporting_evidence=[f"Trace {tid} db_span {db_span}ms / total {duration}ms"],
                        confidence=0.92,
                    ))
            elif duration and duration > 3000:
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                    summary=f"Trace {tid} on {root_span} duration {duration}ms indicates significant latency",
                    supporting_evidence=[f"Trace {tid} duration {duration}ms on {root_span}"],
                    confidence=0.78,
                ))
            # Revision tag in trace
            if t.get("revision"):
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                    summary=f"Trace {tid} executed on revision {t.get('revision')} - confirms blast radius revision attribution",
                    supporting_evidence=[f"Trace {tid} revision {t.get('revision')}"],
                    confidence=0.85,
                    affected_service=evidence.service_name,
                ))
            # Downstream status in trace
            if t.get("db_status") == "DEADLINE_EXCEEDED":
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                    summary=f"Trace {tid} db_span status DEADLINE_EXCEEDED confirms database deadline/timeout, not caller bug",
                    supporting_evidence=[f"Trace {tid} db_status DEADLINE_EXCEEDED duration {t.get('db_span_duration_ms')}ms"],
                    confidence=0.92,
                ))

        # Build dependency path summary
        if deps:
            path = "Client -> " + " -> ".join([evidence.service_name] + [d.get("name") for d in deps if d.get("name")])
            # Find origin vs affected
            failing = [d.get("name") for d in deps if d.get("status") in ("UNAVAILABLE","UNREACHABLE","ERROR")]
            if failing:
                origin = failing[0]
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
                    summary=f"Dependency path: {path} | Origin of failure: {origin} | Affected: {evidence.service_name} (and downstream callers)",
                    supporting_evidence=[f"Path {path}", f"Origin {origin}"],
                    confidence=0.90,
                ))
            else:
                findings.append(AgentFinding(
                    agent_name=self.agent_name,
                    finding_type=FindingType.DEPENDENCY_BOTTLENECK,
                    evidence_strength=EvidenceStrength.CORRELATED_EVIDENCE,
                    summary=f"Dependency path: {path} | No failing downstream detected - failure likely originates in {evidence.service_name} itself",
                    supporting_evidence=[f"Path {path} all dependencies healthy"],
                    confidence=0.75,
                    affected_service=evidence.service_name,
                ))

        return findings
