"""
SQLite schema migrations for Cloud Incident RCA Agent.
"""
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List

SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Schema version table
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT
);

-- Projects
CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    environment TEXT DEFAULT 'production',
    team_owner TEXT DEFAULT '',
    repository_url TEXT DEFAULT '',
    provider TEXT DEFAULT 'github',
    default_branch TEXT DEFAULT 'main',
    local_path TEXT DEFAULT '',
    gcp_project_id TEXT DEFAULT '',
    region TEXT DEFAULT 'us-central1',
    services_json TEXT DEFAULT '[]',
    service_mappings_json TEXT DEFAULT '{}',
    readiness_json TEXT DEFAULT '{}',
    status TEXT DEFAULT 'active',
    created_at TEXT NOT NULL,
    last_scan TEXT DEFAULT '',
    detected_json TEXT DEFAULT '{}',
    data_sources_json TEXT DEFAULT '[]',
    repo_access TEXT DEFAULT 'READ_ONLY',
    demo_mode INTEGER DEFAULT 0
);

-- Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL DEFAULT 'unassigned',
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity TEXT DEFAULT 'P2',
    status TEXT DEFAULT 'NEW',
    source TEXT DEFAULT 'MANUAL',
    evidence_source TEXT DEFAULT 'manual',
    scenario_id TEXT DEFAULT '',
    is_simulation INTEGER DEFAULT 0,
    affected_services_json TEXT DEFAULT '[]',
    started_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT DEFAULT '',
    resolution_reason TEXT DEFAULT '',
    error_domain TEXT DEFAULT '',
    error_subcategory TEXT DEFAULT '',
    pr_id TEXT DEFAULT '',
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);

CREATE INDEX IF NOT EXISTS idx_incidents_project_id ON incidents(project_id);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_started_at ON incidents(started_at);

-- RCA Runs
CREATE TABLE IF NOT EXISTS rca_runs (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    analysis_session_id TEXT DEFAULT '',
    status TEXT DEFAULT 'PENDING',
    root_cause_code TEXT DEFAULT '',
    root_cause_summary TEXT DEFAULT '',
    confidence REAL DEFAULT 0.0,
    quality_score REAL DEFAULT 0.0,
    requires_remediation INTEGER DEFAULT 0,
    requires_code_fix INTEGER DEFAULT 0,
    requires_approval INTEGER DEFAULT 0,
    requires_pr INTEGER DEFAULT 0,
    result_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    started_at TEXT DEFAULT '',
    completed_at TEXT DEFAULT '',
    error TEXT DEFAULT '',
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_rca_runs_incident_id ON rca_runs(incident_id);
CREATE INDEX IF NOT EXISTS idx_rca_runs_created_at ON rca_runs(created_at);

-- Analysis Sessions
CREATE TABLE IF NOT EXISTS analysis_sessions (
    session_id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    analysis_ids_json TEXT DEFAULT '[]',
    context_json TEXT DEFAULT '{}',
    converted_incident_id TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id) REFERENCES projects(project_id)
);

-- Code Fixes
CREATE TABLE IF NOT EXISTS code_fixes (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    rca_run_id TEXT DEFAULT '',
    project_id TEXT DEFAULT '',
    repository TEXT DEFAULT 'cloud-rca-demo-app',
    base_branch TEXT DEFAULT 'main',
    proposed_branch TEXT DEFAULT '',
    status TEXT DEFAULT 'SUGGESTED',
    title TEXT DEFAULT '',
    summary TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    risk TEXT DEFAULT 'LOW',
    fix_confidence REAL DEFAULT 0.0,
    patch_sha256 TEXT DEFAULT '',
    diff_text TEXT DEFAULT '',
    files_json TEXT DEFAULT '[]',
    tests_json TEXT DEFAULT '[]',
    test_result_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (rca_run_id) REFERENCES rca_runs(id)
);

CREATE INDEX IF NOT EXISTS idx_code_fixes_incident_id ON code_fixes(incident_id);
CREATE INDEX IF NOT EXISTS idx_code_fixes_rca_run_id ON code_fixes(rca_run_id);
CREATE INDEX IF NOT EXISTS idx_code_fixes_status ON code_fixes(status);

-- Fix Jobs
CREATE TABLE IF NOT EXISTS fix_jobs (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    status TEXT DEFAULT 'SUGGESTED',
    root_cause_category TEXT DEFAULT '',
    branch TEXT DEFAULT '',
    commit_sha TEXT DEFAULT '',
    pr_number INTEGER DEFAULT 0,
    pr_url TEXT DEFAULT '',
    patch_sha256 TEXT DEFAULT '',
    approval_id TEXT DEFAULT '',
    test_output TEXT DEFAULT '',
    error TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_fix_jobs_incident_id ON fix_jobs(incident_id);
CREATE INDEX IF NOT EXISTS idx_fix_jobs_status ON fix_jobs(status);

-- Approvals
CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    rationale TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    confidence REAL NOT NULL,
    risk TEXT NOT NULL,
    expected_impact TEXT NOT NULL,
    rollback_plan TEXT NOT NULL,
    expiration_time TEXT NOT NULL,
    status TEXT DEFAULT 'PENDING',
    action_type TEXT DEFAULT 'INFRASTRUCTURE_ACTION',
    patch_sha256 TEXT DEFAULT '',
    decided_at TEXT DEFAULT '',
    decided_by TEXT DEFAULT '',
    decided_message TEXT DEFAULT '',
    requested_at TEXT NOT NULL,
    execution_status TEXT DEFAULT '',
    execution_result_json TEXT DEFAULT '{}',
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_approvals_incident_id ON approvals(incident_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_rca_run_id ON approvals(action_type);  -- for CODE_CHANGE

-- Pull Requests
CREATE TABLE IF NOT EXISTS pull_requests (
    id TEXT PRIMARY KEY,
    provider TEXT DEFAULT 'github',
    project_id TEXT DEFAULT '',
    incident_id TEXT DEFAULT '',
    rca_run_id TEXT DEFAULT '',
    code_fix_id TEXT DEFAULT '',
    fix_job_id TEXT DEFAULT '',
    repository TEXT DEFAULT '',
    pr_number INTEGER DEFAULT 0,
    title TEXT DEFAULT '',
    url TEXT DEFAULT '',
    source_branch TEXT DEFAULT '',
    target_branch TEXT DEFAULT '',
    status TEXT DEFAULT 'OPEN',
    checks_state TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    merged_at TEXT DEFAULT '',
    closed_at TEXT DEFAULT '',
    merge_commit_sha TEXT DEFAULT '',
    provider_payload_json TEXT DEFAULT '{}',
    root_cause TEXT DEFAULT '',
    root_cause_category TEXT DEFAULT '',
    confidence REAL DEFAULT 0.0,
    risk TEXT DEFAULT '',
    tests_status TEXT DEFAULT '',
    tests_output TEXT DEFAULT '',
    files_changed_json TEXT DEFAULT '[]',
    additions INTEGER DEFAULT 0,
    deletions INTEGER DEFAULT 0,
    diff TEXT DEFAULT '',
    approval_id TEXT DEFAULT '',
    approved_by TEXT DEFAULT '',
    approved_at TEXT DEFAULT '',
    external_url TEXT DEFAULT '',
    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (rca_run_id) REFERENCES rca_runs(id),
    FOREIGN KEY (code_fix_id) REFERENCES code_fixes(id),
    FOREIGN KEY (fix_job_id) REFERENCES fix_jobs(id)
);

CREATE INDEX IF NOT EXISTS idx_pull_requests_incident_id ON pull_requests(incident_id);
CREATE INDEX IF NOT EXISTS idx_pull_requests_rca_run_id ON pull_requests(rca_run_id);
CREATE INDEX IF NOT EXISTS idx_pull_requests_code_fix_id ON pull_requests(code_fix_id);
CREATE INDEX IF NOT EXISTS idx_pull_requests_status ON pull_requests(status);
CREATE INDEX IF NOT EXISTS idx_pull_requests_project_id ON pull_requests(project_id);

-- Verification Results
CREATE TABLE IF NOT EXISTS verification_results (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    execution_id TEXT DEFAULT '',
    verification_status TEXT DEFAULT 'PENDING',
    summary TEXT DEFAULT '',
    error_rate_before REAL DEFAULT 0.0,
    error_rate_after REAL DEFAULT 0.0,
    latency_before REAL DEFAULT 0.0,
    latency_after REAL DEFAULT 0.0,
    metrics_before_json TEXT DEFAULT '{}',
    metrics_after_json TEXT DEFAULT '{}',
    resolution_checks_json TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_verification_results_incident_id ON verification_results(incident_id);

-- Activity Events (Audit Log)
CREATE TABLE IF NOT EXISTS activity_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    incident_id TEXT DEFAULT '',
    description TEXT DEFAULT '',
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_activity_events_incident_id ON activity_events(incident_id);
CREATE INDEX IF NOT EXISTS idx_activity_events_timestamp ON activity_events(timestamp);

-- Incident Memory (for similar incident retrieval)
CREATE TABLE IF NOT EXISTS incident_memory (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL UNIQUE,
    service TEXT DEFAULT '',
    symptoms_json TEXT DEFAULT '[]',
    timeline_json TEXT DEFAULT '[]',
    root_cause TEXT DEFAULT '',
    root_cause_category TEXT DEFAULT '',
    supporting_evidence_json TEXT DEFAULT '[]',
    blast_radius_json TEXT DEFAULT '{}',
    remediation_json TEXT DEFAULT '{}',
    approval_outcome TEXT DEFAULT '',
    execution_result_json TEXT DEFAULT '{}',
    verification_result_json TEXT DEFAULT '{}',
    final_status TEXT DEFAULT '',
    timestamps_json TEXT DEFAULT '{}',
    confidence REAL DEFAULT 0.0,
    code_paths_json TEXT DEFAULT '[]',
    error_signatures_json TEXT DEFAULT '[]',
    resolution_json TEXT DEFAULT '{}',
    pr_id TEXT DEFAULT '',
    verification_outcome TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_incident_memory_root_cause_category ON incident_memory(root_cause_category);
CREATE INDEX IF NOT EXISTS idx_incident_memory_service ON incident_memory(service);
CREATE INDEX IF NOT EXISTS idx_incident_memory_created_at ON incident_memory(created_at);

-- Idempotency Keys (for safe retries)
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_keys_expires ON idempotency_keys(expires_at);
"""

# All migration statements (version 1 is the initial schema)
MIGRATIONS: List[str] = [
    SCHEMA_SQL,
]


def get_current_version(conn: sqlite3.Connection) -> int:
    """Get current schema version."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT version FROM schema_version ORDER BY version DESC LIMIT 1")
        row = cursor.fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


def set_version(conn: sqlite3.Connection, version: int, description: str = "") -> None:
    """Set schema version."""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
        (version, datetime.utcnow().isoformat(), description)
    )
    conn.commit()


def run_migrations(conn: sqlite3.Connection) -> None:
    """Run all pending migrations."""
    current = get_current_version(conn)
    target = len(MIGRATIONS)

    if current >= target:
        return

    for version in range(current + 1, target + 1):
        migration_sql = MIGRATIONS[version - 1]
        # Execute as a script (handles multiple statements)
        conn.executescript(migration_sql)
        set_version(conn, version, f"Migration v{version}")
        conn.commit()


def init_database(db_path: str) -> sqlite3.Connection:
    """Initialize database with migrations."""
    # Ensure parent directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    # Configure SQLite for better concurrency
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.execute("PRAGMA busy_timeout=5000;")

    run_migrations(conn)
    return conn