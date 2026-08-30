"""
Unit tests for EvidenceExtractor.
"""
from tools.evidence_extractor import EvidenceExtractor
from agents.rca_agent.schemas import LogEntry, LogLevel, IncidentContext


def test_extract_evidence_db_pool():
    entries = [
        LogEntry(
            timestamp="2026-08-30T14:00:00Z",
            service="payment-api",
            level=LogLevel.ERROR,
            message="ConnectionPoolTimeout: Could not acquire connection from HikariCP pool",
            raw_log="raw log line"
        )
    ]
    ctx = IncidentContext(
        incident_id="INC-001",
        title="Test Inc",
        description="Test",
        services_involved=["payment-api"],
        start_time="2026-08-30T14:00:00Z",
        log_files=[]
    )

    evidence = EvidenceExtractor.extract_evidence(entries, ctx)
    assert len(evidence) == 1
    assert evidence[0].type == "DATABASE_POOL_EXHAUSTION"
    assert evidence[0].relevance_score >= 0.90
