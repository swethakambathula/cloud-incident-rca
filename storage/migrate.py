"""
One-time migration from JSON/JSONL files to SQLite.

Run this once after deploying the SQLite storage layer.
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.sqlite_store import SQLiteStore, get_store
from storage.models import (
    ProjectModel, IncidentModel, RCARunModel, AnalysisSessionModel,
    CodeFixModel, FixJobModel, ApprovalModel, PullRequestModel,
    ActivityEventModel, IncidentMemoryModel
)


BASE = Path(__file__).parent.parent / "data"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def migrate_projects(store: SQLiteStore) -> int:
    """Migrate projects from projects.json."""
    projects_file = BASE / "projects.json"
    if not projects_file.exists():
        print("No projects.json found, skipping")
        return 0

    with open(projects_file, encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    for project_id, p in data.items():
        project = ProjectModel(
            project_id=project_id,
            name=p.get("name", project_id),
            description=p.get("description", ""),
            environment=p.get("environment", "production"),
            team_owner=p.get("team_owner", ""),
            repository_url=p.get("repository_url", ""),
            provider=p.get("provider", "github"),
            default_branch=p.get("default_branch", "main"),
            local_path=p.get("local_path", ""),
            gcp_project_id=p.get("gcp_project_id", ""),
            region=p.get("region", "us-central1"),
            services_json=json.dumps(p.get("services", [])),
            service_mappings_json=json.dumps(p.get("service_mappings", {})),
            readiness_json=json.dumps(p.get("readiness", {})),
            status=p.get("status", "active"),
            created_at=p.get("created_at", _now()),
            last_scan=p.get("last_scan", ""),
            detected_json=json.dumps(p.get("detected", {})),
            data_sources_json=json.dumps(p.get("data_sources", [])),
            repo_access=p.get("repo_access", "READ_ONLY"),
            demo_mode=p.get("demo_mode", False)
        )
        store.save_project(project)
        count += 1
    print(f"Migrated {count} projects")
    return count


def migrate_incidents(store: SQLiteStore) -> int:
    """Migrate incidents from incidents.json and activity.jsonl."""
    incidents_file = BASE / "incidents.json"
    if not incidents_file.exists():
        print("No incidents.json found, skipping")
        return 0

    # Ensure "unassigned" project exists
    if not store.get_project("unassigned"):
        store.save_project(ProjectModel(
            project_id="unassigned",
            name="Unassigned",
            description="Default project for incidents without explicit project",
            environment="production",
            created_at=_now()
        ))

    with open(incidents_file, encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    for incident_id, rec in data.items():
        # Normalize source
        source = (rec.get("source") or "MANUAL").upper()
        is_sim = source == "SIMULATION"

        project_id = rec.get("project_id", "unassigned")
        if not store.get_project(project_id):
            project_id = "unassigned"

        incident = IncidentModel(
            id=incident_id,
            project_id=project_id,
            title=rec.get("title", incident_id),
            description=rec.get("description", ""),
            severity=rec.get("severity", "P2"),
            status=rec.get("status", "NEW"),
            source=source,
            evidence_source=rec.get("evidence_source", source.lower()),
            scenario_id=rec.get("scenario_id", ""),
            is_simulation=is_sim,
            affected_services_json=json.dumps(rec.get("services", [])),
            started_at=rec.get("started_at", _now()),
            created_at=rec.get("started_at", _now()),
            updated_at=_now(),
            resolved_at=rec.get("resolved_at", "") or "",
            resolution_reason=rec.get("resolution_reason", "") or "",
            error_domain=rec.get("error_domain", "") or "",
            error_subcategory=rec.get("error_subcategory", "") or "",
            pr_id=rec.get("pr_id", "") or ""
        )
        store.save_incident(incident)

        # Migrate RCA runs
        for run in rec.get("rca_runs", []):
            run_id = f"RCA-{incident_id}-{run.get('run_number', 1)}"
            rca_run = RCARunModel(
                id=run_id,
                incident_id=incident_id,
                analysis_session_id="",
                status="COMPLETED",
                root_cause_code=run.get("category", ""),
                root_cause_summary=run.get("category", ""),
                confidence=run.get("confidence", 0.0),
                quality_score=0.0,
                requires_remediation=1,
                requires_code_fix=0,
                requires_approval=0,
                requires_pr=0,
                result_json=json.dumps(run),
                created_at=run.get("at", _now()),
                started_at=run.get("at", _now()),
                completed_at=run.get("at", _now()),
                error=""
            )
            store.save_rca_run(rca_run)

        count += 1

    # Also migrate activity events
    activity_file = BASE / "activity.jsonl"
    if activity_file.exists():
        with open(activity_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    activity = ActivityEventModel(
                        id=f"ACT-{count}-{entry.get('timestamp', '')[:10]}",
                        timestamp=entry.get("timestamp", _now()),
                        actor=entry.get("actor", "system"),
                        event=entry.get("event", ""),
                        incident_id=entry.get("incident_id", ""),
                        description=entry.get("description", ""),
                        metadata_json=json.dumps(entry.get("metadata", {}))
                    )
                    # Use direct insert to avoid duplicate append_activity calls
                    store._execute(
                        "INSERT OR IGNORE INTO activity_events (id, timestamp, actor, event, incident_id, description, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (activity.id, activity.timestamp, activity.actor, activity.event,
                         activity.incident_id, activity.description, activity.metadata_json)
                    )
                except Exception as e:
                    print(f"  Skipping activity entry: {e}")

    store._get_conn().commit()
    print(f"Migrated {count} incidents")
    return count


def migrate_prs(store: SQLiteStore) -> int:
    """Migrate PRs from agent_prs.jsonl."""
    prs_file = BASE / "agent_prs.jsonl"
    if not prs_file.exists():
        print("No agent_prs.jsonl found, skipping")
        return 0

    count = 0
    with open(prs_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                pr = PullRequestModel(
                    id=r.get("pr_id", f"PR-{count}"),
                    provider=r.get("provider", "github"),
                    project_id=r.get("project_id", ""),
                    incident_id=r.get("incident_id", ""),
                    rca_run_id=r.get("rca_run_id") or None,
                    code_fix_id=r.get("code_fix_id") or None,
                    fix_job_id=r.get("fix_job_id") or None,
                    repository=r.get("repository", ""),
                    pr_number=r.get("pr_number", 0),
                    title=r.get("title", ""),
                    url=r.get("url", ""),
                    source_branch=r.get("branch", ""),
                    target_branch=r.get("base_branch", "main"),
                    status=r.get("status", "OPEN"),
                    checks_state=r.get("checks_state", ""),
                    created_at=r.get("created_at", _now()),
                    updated_at=r.get("updated_at", _now()),
                    merged_at=r.get("merged_at") or None,
                    closed_at=r.get("closed_at") or None,
                    merge_commit_sha=r.get("merge_commit_sha") or None,
                    provider_payload_json=json.dumps(r.get("provider_payload", {})),
                    root_cause=r.get("root_cause", ""),
                    root_cause_category=r.get("root_cause_category", ""),
                    confidence=r.get("confidence", 0.0),
                    risk=r.get("risk", ""),
                    tests_status=r.get("tests_status", ""),
                    tests_output=r.get("tests_output", ""),
                    files_changed_json=json.dumps(r.get("files_changed", [])),
                    additions=r.get("additions", 0),
                    deletions=r.get("deletions", 0),
                    diff=r.get("diff", ""),
                    approval_id=r.get("approval_id") or None,
                    approved_by=r.get("approved_by") or None,
                    approved_at=r.get("approved_at") or None,
                    external_url=r.get("external_url") or None
                )
                store.save_pull_request(pr)
                count += 1
            except Exception as e:
                print(f"  Skipping PR entry: {e}")

    print(f"Migrated {count} PRs")
    return count


def migrate_incident_memory(store: SQLiteStore) -> int:
    """Migrate incident memory from incident_memory.jsonl."""
    memory_file = BASE / "incident_memory.jsonl"
    if not memory_file.exists():
        print("No incident_memory.jsonl found, skipping")
        return 0

    count = 0
    with open(memory_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                incident_id = r.get("incident_id", "")
                # Skip if incident doesn't exist (FK constraint)
                if incident_id and not store.get_incident(incident_id):
                    print(f"  Skipping memory for non-existent incident: {incident_id}")
                    continue
                memory = IncidentMemoryModel(
                    id=f"MEM-{r.get('incident_id', f'unknown-{count}')}",
                    incident_id=incident_id,
                    service=r.get("service", ""),
                    symptoms_json=json.dumps(r.get("symptoms", [])),
                    timeline_json=json.dumps(r.get("timeline", [])),
                    root_cause=r.get("root_cause", ""),
                    root_cause_category=r.get("root_cause_category", ""),
                    supporting_evidence_json=json.dumps(r.get("supporting_evidence", [])),
                    blast_radius_json=json.dumps(r.get("blast_radius", {})),
                    remediation_json=json.dumps(r.get("remediation", {})),
                    approval_outcome=r.get("approval_outcome", "") or "",
                    execution_result_json=json.dumps(r.get("execution_result", {})),
                    verification_result_json=json.dumps(r.get("verification_result", {})),
                    final_status=r.get("final_status", "") or "",
                    timestamps_json=json.dumps(r.get("timestamps", {})),
                    confidence=r.get("confidence", 0.0),
                    code_paths_json=json.dumps(r.get("code_paths", [])),
                    error_signatures_json=json.dumps(r.get("error_signatures", [])),
                    resolution_json=json.dumps(r.get("resolution", {})),
                    pr_id=r.get("pr_id", "") or "",
                    verification_outcome=r.get("verification_outcome", "") or "",
                    created_at=r.get("created_at", _now())
                )
                store.save_incident_memory(memory)
                count += 1
            except Exception as e:
                print(f"  Skipping memory entry: {e}")

    print(f"Migrated {count} incident memory records")
    return count


def migrate_analysis_sessions(store: SQLiteStore) -> int:
    """Migrate analysis sessions from analysis_sessions.json."""
    sessions_file = BASE / "analysis_sessions.json"
    if not sessions_file.exists():
        print("No analysis_sessions.json found, skipping")
        return 0

    with open(sessions_file, encoding="utf-8") as f:
        data = json.load(f)

    count = 0
    for session_id, rec in data.items():
        session = AnalysisSessionModel(
            session_id=session_id,
            project_id=rec.get("project_id", "unassigned"),
            analysis_ids_json=json.dumps(rec.get("analysis_ids", [])),
            context_json=json.dumps(rec.get("context", {})),
            converted_incident_id=rec.get("converted_incident_id", ""),
            created_at=rec.get("created_at", _now())
        )
        store.save_analysis_session(session)
        count += 1

    print(f"Migrated {count} analysis sessions")
    return count


def migrate_log_analyses(store: SQLiteStore) -> int:
    """Migrate log analyses - they are stored in incident_registry and analysis_sessions."""
    # These are already covered by incidents and analysis_sessions
    analyses_file = BASE / "log_analyses.jsonl"
    if not analyses_file.exists():
        return 0
    count = 0
    with open(analyses_file, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
                # Create analysis session if not exists
                session_id = r.get("analysis_id", "")
                if session_id:
                    existing = store.get_analysis_session(session_id)
                    if not existing:
                        session = AnalysisSessionModel(
                            session_id=session_id,
                            project_id=r.get("project_id", "unassigned"),
                            analysis_ids_json=json.dumps([session_id]),
                            context_json=json.dumps(r.get("context", {})),
                            converted_incident_id=(r.get("rca", {}).get("incident_id") if r.get("rca") else "") or "",
                            created_at=r.get("created_at", _now())
                        )
                        store.save_analysis_session(session)
                        count += 1
            except Exception as e:
                print(f"  Skipping analysis entry: {e}")

    print(f"Migrated {count} analysis sessions from log_analyses")
    return count


def run_migration(db_path: Optional[str] = None) -> None:
    """Run all migrations."""
    print("Starting migration to SQLite...")
    print(f"Database: {db_path or 'default (data/cloud_rca.db)'}")

    store = get_store(db_path)

    # Check if already migrated
    stats = store.get_stats()
    if stats.get("projects", 0) > 0 or stats.get("incidents", 0) > 0:
        print("Database already has data. Skipping migration to avoid duplicates.")
        print(f"Current stats: {stats}")
        return

    total = 0
    total += migrate_projects(store)
    total += migrate_incidents(store)
    total += migrate_prs(store)
    total += migrate_incident_memory(store)
    total += migrate_analysis_sessions(store)
    total += migrate_log_analyses(store)

    print(f"\nMigration complete! Total records migrated: {total}")
    print(f"Final stats: {store.get_stats()}")


if __name__ == "__main__":
    db_path = os.getenv("CLOUD_RCA_DB_PATH")
    run_migration(db_path)