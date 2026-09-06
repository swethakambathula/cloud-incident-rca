"""
Unit tests for Phase 3 schemas and shared InvestigationState.
"""
from schemas.evidence import IncidentEvidence
from schemas.findings import AgentFinding, FindingType, EvidenceStrength, KnowledgeFinding
from schemas.hypothesis import RootCauseHypothesis
from schemas.validation import HypothesisValidation, ValidationStatus
from schemas.report import BlastRadiusResult, IncidentReport, TimelineEvent
from orchestration.state import InvestigationState, AgentExecutionTrace


def test_investigation_state_lifecycle():
    evidence = IncidentEvidence(
        incident_id="INC-STATE-01",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="test-proj",
        service_name="checkout-service",
        severity="P1",
        symptoms=["HTTP 500 spike"]
    )
    state = InvestigationState(incident_id=evidence.incident_id, incident_evidence=evidence)

    # 1. Plan
    state.set_investigation_plan(["analyze_logs", "analyze_metrics", "check_deployments"])
    assert len(state.pending_tasks) == 3
    state.record_task_completion("analyze_logs")
    assert len(state.pending_tasks) == 2
    assert "analyze_logs" in state.completed_tasks

    # 2. Add Findings
    finding = AgentFinding(
        agent_name="LogAgent",
        finding_type=FindingType.ERROR_PATTERN,
        evidence_strength=EvidenceStrength.DIRECT_EVIDENCE,
        summary="High frequency of DATABASE_CONNECTION_TIMEOUT",
        supporting_evidence=["148 logs observed"],
        confidence=0.92,
        related_error_codes=["DATABASE_CONNECTION_TIMEOUT"]
    )
    state.add_agent_finding(finding)
    assert len(state.agent_findings) == 1

    # 3. Add Knowledge Finding
    k_finding = KnowledgeFinding(
        source_id="runbooks/database-timeout.md",
        source_type="runbook",
        title="Database Timeout Runbook",
        relevant_excerpt_summary="Check VPC egress and Cloud SQL instance",
        relevance_reason="Matches DATABASE_CONNECTION_TIMEOUT",
        associated_failure_pattern="database_connectivity"
    )
    state.add_knowledge_findings([k_finding])
    assert len(state.knowledge_findings) == 1

    # 4. Add Hypotheses
    hyp = RootCauseHypothesis(
        hypothesis_id="HYP-001",
        root_cause="Database connectivity failure",
        root_cause_category="database_connectivity",
        confidence_score=0.90,
        supporting_evidence=["DATABASE_CONNECTION_TIMEOUT logs"],
        reasoning_summary="Direct log errors without CPU increase"
    )
    state.set_hypotheses([hyp])
    assert len(state.hypotheses) == 1

    # 5. Add Validation Result
    val = HypothesisValidation(
        hypothesis_id="HYP-001",
        validation_status=ValidationStatus.SUPPORTED,
        accepted=True,
        adjusted_confidence=0.92,
        supporting_evidence_strength="STRONG",
        critic_reasoning="Evidence aligns with database reachability failure"
    )
    state.add_validation_result(val)
    assert len(state.validated_hypotheses) == 1
    assert len(state.rejected_hypotheses) == 0

    # 6. Retry bounding
    res1 = state.increment_round_with_tasks(["investigate_connection_pool"])
    assert res1 is True
    assert state.investigation_round == 2

    res2 = state.increment_round_with_tasks(["investigate_db_cpu"])
    assert res2 is True
    assert state.investigation_round == 3

    # Round 4 should be rejected (max_rounds = 3)
    res3 = state.increment_round_with_tasks(["investigate_more"])
    assert res3 is False
    assert state.investigation_status == "MAX_ROUNDS_REACHED"
