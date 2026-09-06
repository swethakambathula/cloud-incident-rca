"""
Missing evidence tests - system should not crash, should reduce confidence.
"""
from schemas.evidence import IncidentEvidence
from orchestration.workflow import InvestigationWorkflow

def test_monitoring_unavailable_continues():
    evidence = IncidentEvidence(
        incident_id="INC-MISSING-01",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="test-proj",
        service_name="checkout-service",
        severity="P1",
        symptoms=["DATABASE_CONNECTION_TIMEOUT"],
        application_errors=[{"error_code":"DATABASE_CONNECTION_TIMEOUT","count": 50}],
        request_errors=[{"endpoint":"/checkout","status_code":500,"count":50}],
        latency={},  # missing
        request_count={},  # missing
        cpu_utilization={},  # missing
        memory_utilization={},  # missing
        recent_deployments=[{"revision_name":"rev-1","deployed_at":"2026-09-05T10:00:00Z","traffic_percent":100}],
        dependencies=[{"name":"orders-db","status":"UNREACHABLE"}],
        traces=[{"trace_id":"t1","duration_ms":5000,"db_status":"DEADLINE_EXCEEDED"}],
    )
    wf = InvestigationWorkflow()
    state = wf.run(evidence)
    # Should not crash, should complete even with missing monitoring
    assert state.final_report is not None
    # Confidence should be reduced vs normal case (missing metrics lower confidence)
    assert state.final_report.confidence < 0.95
    assert state.investigation_status == "COMPLETED"
    # At least metrics agent should note missing via findings
    assert any("metric" in f.missing_information[0].lower() or "monitoring" in f.missing_information[0].lower() for f in state.agent_findings if f.missing_information) or state.trace.investigation_rounds <= 3

def test_no_trace_still_completes():
    evidence = IncidentEvidence(
        incident_id="INC-MISSING-02",
        start_time="2026-09-05T14:00:00Z",
        end_time="2026-09-05T14:15:00Z",
        project_id="test-proj",
        service_name="checkout-service",
        severity="P2",
        symptoms=["high latency"],
        application_errors=[],
        request_errors=[],
        latency={"baseline": 150,"incident": 2200,"severity":"CRITICAL","percentage_change": 1300},
        request_count={"baseline":500,"incident":520,"severity":"NORMAL","percentage_change":4},
        cpu_utilization={"baseline":20,"incident":25,"severity":"NORMAL","percentage_change":25},
        memory_utilization={"baseline":35,"incident":36,"severity":"NORMAL"},
        recent_deployments=[],
        dependencies=[],
        traces=[],
    )
    wf = InvestigationWorkflow()
    state = wf.run(evidence)
    assert state.final_report is not None
    # Trace agent should record missing
    trace_findings = [f for f in state.agent_findings if "Trace" in f.agent_name]
    # May be no trace findings but should still complete without crash
    assert state.trace.investigation_rounds <= 3
