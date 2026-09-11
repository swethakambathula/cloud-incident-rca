"""
SQLite-backed persistent storage for Cloud Incident RCA Agent.

This module provides a storage abstraction layer over SQLite for all
persistent data: incidents, RCA runs, code fixes, approvals, PRs, etc.
"""
import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from storage.migrations import init_database, get_current_version
from storage.models import (
    ProjectModel, IncidentModel, RCARunModel, AnalysisSessionModel,
    CodeFixModel, FixJobModel, ApprovalModel, PullRequestModel,
    VerificationResultModel, ActivityEventModel, IncidentMemoryModel,
    IdempotencyKeyModel
)


class SQLiteStore:
    """Main SQLite storage class with domain-specific methods."""

    _instance: Optional['SQLiteStore'] = None
    _lock = threading.Lock()

    def __new__(cls, db_path: Optional[str] = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, db_path: Optional[str] = None):
        if self._initialized:
            return

        if db_path is None:
            db_path = os.getenv("CLOUD_RCA_DB_PATH")
        if db_path is None:
            base_dir = Path(__file__).parent.parent
            db_path = str(base_dir / "data" / "cloud_rca.db")

        self.db_path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._local = threading.local()
        self._initialized = True

    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = init_database(self.db_path)
        return self._local.conn

    def close(self) -> None:
        """Close thread-local connection."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ============================================================
    # Helper methods
    # ============================================================

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _execute(self, sql: str, params: Tuple = ()) -> sqlite3.Cursor:
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(sql, params)
        return cursor

    def _execute_many(self, sql: str, params_list: List[Tuple]) -> None:
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.executemany(sql, params_list)
        conn.commit()

    def _fetchone(self, sql: str, params: Tuple = ()) -> Optional[sqlite3.Row]:
        cursor = self._execute(sql, params)
        return cursor.fetchone()

    def _fetchall(self, sql: str, params: Tuple = ()) -> List[sqlite3.Row]:
        cursor = self._execute(sql, params)
        return cursor.fetchall()

    def _transaction(self):
        """Context manager for transactions."""
        return self._get_conn()

    # ============================================================
    # Projects
    # ============================================================

    def save_project(self, project: ProjectModel) -> ProjectModel:
        sql = """
            INSERT OR REPLACE INTO projects (
                project_id, name, description, environment, team_owner,
                repository_url, provider, default_branch, local_path,
                gcp_project_id, region, services_json, service_mappings_json,
                readiness_json, status, created_at, last_scan,
                detected_json, data_sources_json, repo_access, demo_mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            project.project_id, project.name, project.description, project.environment,
            project.team_owner, project.repository_url, project.provider,
            project.default_branch, project.local_path, project.gcp_project_id,
            project.region, project.services_json, project.service_mappings_json,
            project.readiness_json, project.status, project.created_at,
            project.last_scan, project.detected_json, project.data_sources_json,
            project.repo_access, int(project.demo_mode)
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return project

    def get_project(self, project_id: str) -> Optional[ProjectModel]:
        row = self._fetchone("SELECT * FROM projects WHERE project_id = ?", (project_id,))
        if row:
            return ProjectModel(**dict(row))
        return None

    def list_projects(self) -> List[ProjectModel]:
        rows = self._fetchall("SELECT * FROM projects ORDER BY created_at DESC")
        return [ProjectModel(**dict(row)) for row in rows]

    def delete_project(self, project_id: str) -> bool:
        if project_id == "checkout-platform":
            return False
        cursor = self._execute("DELETE FROM projects WHERE project_id = ?", (project_id,))
        self._get_conn().commit()
        return cursor.rowcount > 0

    # ============================================================
    # Incidents
    # ============================================================

    def save_incident(self, incident: IncidentModel) -> IncidentModel:
        sql = """
            INSERT OR REPLACE INTO incidents (
                id, project_id, title, description, severity, status, source,
                evidence_source, scenario_id, is_simulation, affected_services_json,
                started_at, created_at, updated_at, resolved_at, resolution_reason,
                error_domain, error_subcategory, pr_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            incident.id, incident.project_id, incident.title, incident.description,
            incident.severity, incident.status, incident.source, incident.evidence_source,
            incident.scenario_id, int(incident.is_simulation), incident.affected_services_json,
            incident.started_at, incident.created_at, incident.updated_at,
            incident.resolved_at, incident.resolution_reason, incident.error_domain,
            incident.error_subcategory, incident.pr_id
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return incident

    def get_incident(self, incident_id: str) -> Optional[IncidentModel]:
        row = self._fetchone("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if row:
            return IncidentModel(**dict(row))
        return None

    def list_incidents(self, project_id: str = "", status: str = "",
                       limit: int = 100, offset: int = 0) -> List[IncidentModel]:
        sql = "SELECT * FROM incidents WHERE 1=1"
        params = []
        if project_id:
            sql += " AND project_id = ?"
            params.append(project_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = self._fetchall(sql, tuple(params))
        return [IncidentModel(**dict(row)) for row in rows]

    def transition_incident(self, incident_id: str, target_status: str,
                            actor: str = "system") -> Optional[IncidentModel]:
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        incident.status = target_status
        incident.updated_at = self._now()
        self.save_incident(incident)
        self.append_activity("STATUS_CHANGED", incident_id, actor,
                             f"{incident_id} moved to {target_status}")
        return incident

    def add_rca_run_to_incident(self, incident_id: str, run_id: str) -> None:
        """Add RCA run reference to incident (stored in rca_runs table)."""
        # The rca_runs table already has incident_id FK, so just ensure incident exists
        pass

    def set_incident_pr(self, incident_id: str, pr_id: str) -> None:
        self._execute(
            "UPDATE incidents SET pr_id = ?, updated_at = ? WHERE id = ?",
            (pr_id, self._now(), incident_id)
        )
        self._get_conn().commit()

    def set_incident_fields(self, incident_id: str, **fields) -> Optional[IncidentModel]:
        incident = self.get_incident(incident_id)
        if not incident:
            return None
        for key, value in fields.items():
            if hasattr(incident, key):
                setattr(incident, key, value)
        incident.updated_at = self._now()
        self.save_incident(incident)
        return incident

    # ============================================================
    # RCA Runs
    # ============================================================

    def save_rca_run(self, run: RCARunModel) -> RCARunModel:
        sql = """
            INSERT OR REPLACE INTO rca_runs (
                id, incident_id, analysis_session_id, status, root_cause_code,
                root_cause_summary, confidence, quality_score, requires_remediation,
                requires_code_fix, requires_approval, requires_pr, result_json,
                created_at, started_at, completed_at, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            run.id, run.incident_id, run.analysis_session_id, run.status,
            run.root_cause_code, run.root_cause_summary, run.confidence,
            run.quality_score, run.requires_remediation, run.requires_code_fix,
            run.requires_approval, run.requires_pr, run.result_json,
            run.created_at, run.started_at, run.completed_at, run.error
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return run

    def get_rca_run(self, run_id: str) -> Optional[RCARunModel]:
        row = self._fetchone("SELECT * FROM rca_runs WHERE id = ?", (run_id,))
        if row:
            return RCARunModel(**dict(row))
        return None

    def list_rca_runs(self, incident_id: str = "", limit: int = 50) -> List[RCARunModel]:
        sql = "SELECT * FROM rca_runs WHERE 1=1"
        params = []
        if incident_id:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(sql, tuple(params))
        return [RCARunModel(**dict(row)) for row in rows]

    def get_latest_rca_run(self, incident_id: str) -> Optional[RCARunModel]:
        row = self._fetchone(
            "SELECT * FROM rca_runs WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
            (incident_id,)
        )
        if row:
            return RCARunModel(**dict(row))
        return None

    # ============================================================
    # Analysis Sessions
    # ============================================================

    def save_analysis_session(self, session: AnalysisSessionModel) -> AnalysisSessionModel:
        sql = """
            INSERT OR REPLACE INTO analysis_sessions (
                session_id, project_id, analysis_ids_json, context_json,
                converted_incident_id, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """
        params = (
            session.session_id, session.project_id, session.analysis_ids_json,
            session.context_json, session.converted_incident_id, session.created_at
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return session

    def get_analysis_session(self, session_id: str) -> Optional[AnalysisSessionModel]:
        row = self._fetchone("SELECT * FROM analysis_sessions WHERE session_id = ?", (session_id,))
        if row:
            return AnalysisSessionModel(**dict(row))
        return None

    def list_analysis_sessions(self, project_id: str = "") -> List[AnalysisSessionModel]:
        sql = "SELECT * FROM analysis_sessions WHERE 1=1"
        params = []
        if project_id:
            sql += " AND project_id = ?"
            params.append(project_id)
        sql += " ORDER BY created_at DESC"
        rows = self._fetchall(sql, tuple(params))
        return [AnalysisSessionModel(**dict(row)) for row in rows]

    # ============================================================
    # Code Fixes
    # ============================================================

    def save_code_fix(self, fix: CodeFixModel) -> CodeFixModel:
        sql = """
            INSERT OR REPLACE INTO code_fixes (
                id, incident_id, rca_run_id, project_id, repository, base_branch,
                proposed_branch, status, title, summary, reason, risk, fix_confidence,
                patch_sha256, diff_text, files_json, tests_json, test_result_json,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            fix.id, fix.incident_id, fix.rca_run_id, fix.project_id, fix.repository,
            fix.base_branch, fix.proposed_branch, fix.status, fix.title, fix.summary,
            fix.reason, fix.risk, fix.fix_confidence, fix.patch_sha256, fix.diff_text,
            fix.files_json, fix.tests_json, fix.test_result_json,
            fix.created_at, fix.updated_at
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return fix

    def get_code_fix(self, fix_id: str) -> Optional[CodeFixModel]:
        row = self._fetchone("SELECT * FROM code_fixes WHERE id = ?", (fix_id,))
        if row:
            return CodeFixModel(**dict(row))
        return None

    def get_code_fix_by_incident(self, incident_id: str) -> Optional[CodeFixModel]:
        row = self._fetchone(
            "SELECT * FROM code_fixes WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
            (incident_id,)
        )
        if row:
            return CodeFixModel(**dict(row))
        return None

    def list_code_fixes(self, incident_id: str = "", project_id: str = "",
                        status: str = "", limit: int = 50) -> List[CodeFixModel]:
        sql = "SELECT * FROM code_fixes WHERE 1=1"
        params = []
        if incident_id:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        if project_id:
            sql += " AND project_id = ?"
            params.append(project_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(sql, tuple(params))
        return [CodeFixModel(**dict(row)) for row in rows]

    def list_code_fixes_for_incident_with_rca(self, incident_id: str) -> List[Tuple[CodeFixModel, Optional[RCARunModel]]]:
        """Get all code fixes for an incident with their associated RCA runs."""
        fixes = self.list_code_fixes(incident_id=incident_id)
        result = []
        for fix in fixes:
            rca_run = None
            if fix.rca_run_id:
                rca_run = self.get_rca_run(fix.rca_run_id)
            result.append((fix, rca_run))
        return result

    # ============================================================
    # Fix Jobs
    # ============================================================

    def save_fix_job(self, job: FixJobModel) -> FixJobModel:
        sql = """
            INSERT OR REPLACE INTO fix_jobs (
                id, incident_id, status, root_cause_category, branch, commit_sha,
                pr_number, pr_url, patch_sha256, approval_id, test_output, error,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            job.id, job.incident_id, job.status, job.root_cause_category,
            job.branch, job.commit_sha, job.pr_number, job.pr_url, job.patch_sha256,
            job.approval_id, job.test_output, job.error, job.created_at, job.updated_at
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return job

    def get_fix_job(self, job_id: str) -> Optional[FixJobModel]:
        row = self._fetchone("SELECT * FROM fix_jobs WHERE id = ?", (job_id,))
        if row:
            return FixJobModel(**dict(row))
        return None

    def get_fix_job_by_incident(self, incident_id: str) -> Optional[FixJobModel]:
        row = self._fetchone(
            "SELECT * FROM fix_jobs WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
            (incident_id,)
        )
        if row:
            return FixJobModel(**dict(row))
        return None

    def list_fix_jobs(self, incident_id: str = "", status: str = "",
                      limit: int = 50) -> List[FixJobModel]:
        sql = "SELECT * FROM fix_jobs WHERE 1=1"
        params = []
        if incident_id:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(sql, tuple(params))
        return [FixJobModel(**dict(row)) for row in rows]

    # ============================================================
    # Approvals
    # ============================================================

    def save_approval(self, approval: ApprovalModel) -> ApprovalModel:
        sql = """
            INSERT OR REPLACE INTO approvals (
                approval_id, incident_id, action, target_resource, rationale,
                root_cause, confidence, risk, expected_impact, rollback_plan,
                expiration_time, status, action_type, patch_sha256,
                decided_at, decided_by, decided_message, requested_at,
                execution_status, execution_result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            approval.approval_id, approval.incident_id, approval.action,
            approval.target_resource, approval.rationale, approval.root_cause,
            approval.confidence, approval.risk, approval.expected_impact,
            approval.rollback_plan, approval.expiration_time, approval.status,
            approval.action_type, approval.patch_sha256, approval.decided_at,
            approval.decided_by, approval.decided_message, approval.requested_at,
            approval.execution_status, approval.execution_result_json
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return approval

    def get_approval(self, approval_id: str) -> Optional[ApprovalModel]:
        row = self._fetchone("SELECT * FROM approvals WHERE approval_id = ?", (approval_id,))
        if row:
            return ApprovalModel(**dict(row))
        return None

    def list_approvals(self, incident_id: str = "", status: str = "",
                       action_type: str = "", limit: int = 50) -> List[ApprovalModel]:
        sql = "SELECT * FROM approvals WHERE 1=1"
        params = []
        if incident_id:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if action_type:
            sql += " AND action_type = ?"
            params.append(action_type)
        sql += " ORDER BY requested_at DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(sql, tuple(params))
        return [ApprovalModel(**dict(row)) for row in rows]

    def list_pending_approvals(self) -> List[ApprovalModel]:
        return self.list_approvals(status="PENDING")

    def list_recent_approvals(self, limit: int = 10) -> List[ApprovalModel]:
        sql = """
            SELECT * FROM approvals WHERE status != 'PENDING'
            ORDER BY decided_at DESC LIMIT ?
        """
        rows = self._fetchall(sql, (limit,))
        return [ApprovalModel(**dict(row)) for row in rows]

    # ============================================================
    # Pull Requests
    # ============================================================

    def save_pull_request(self, pr: PullRequestModel) -> PullRequestModel:
        # 35 columns, 35 placeholders
        placeholders = ", ".join(["?"] * 35)
        sql = f"""
            INSERT OR REPLACE INTO pull_requests (
                id, provider, project_id, incident_id, rca_run_id, code_fix_id,
                fix_job_id, repository, pr_number, title, url, source_branch,
                target_branch, status, checks_state, created_at, updated_at,
                merged_at, closed_at, merge_commit_sha, provider_payload_json,
                root_cause, root_cause_category, confidence, risk, tests_status,
                tests_output, files_changed_json, additions, deletions, diff,
                approval_id, approved_by, approved_at, external_url
            ) VALUES ({placeholders})
        """
        params = (
            pr.id, pr.provider, pr.project_id, pr.incident_id, pr.rca_run_id,
            pr.code_fix_id, pr.fix_job_id, pr.repository, pr.pr_number, pr.title,
            pr.url, pr.source_branch, pr.target_branch, pr.status, pr.checks_state,
            pr.created_at, pr.updated_at, pr.merged_at, pr.closed_at,
            pr.merge_commit_sha, pr.provider_payload_json, pr.root_cause,
            pr.root_cause_category, pr.confidence, pr.risk, pr.tests_status,
            pr.tests_output, pr.files_changed_json, pr.additions, pr.deletions,
            pr.diff, pr.approval_id, pr.approved_by, pr.approved_at, pr.external_url
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return pr

    def get_pull_request(self, pr_id: str) -> Optional[PullRequestModel]:
        row = self._fetchone("SELECT * FROM pull_requests WHERE id = ?", (pr_id,))
        if row:
            return PullRequestModel(**dict(row))
        return None

    def get_pull_request_by_number(self, repository: str, pr_number: int) -> Optional[PullRequestModel]:
        row = self._fetchone(
            "SELECT * FROM pull_requests WHERE repository = ? AND pr_number = ?",
            (repository, pr_number)
        )
        if row:
            return PullRequestModel(**dict(row))
        return None

    def list_pull_requests(self, project_id: str = "", incident_id: str = "",
                           status: str = "", limit: int = 50) -> List[PullRequestModel]:
        sql = "SELECT * FROM pull_requests WHERE 1=1"
        params = []
        if project_id:
            sql += " AND project_id = ?"
            params.append(project_id)
        if incident_id:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(sql, tuple(params))
        return [PullRequestModel(**dict(row)) for row in rows]

    def list_pull_requests_for_incident(self, incident_id: str) -> List[PullRequestModel]:
        return self.list_pull_requests(incident_id=incident_id)

    # ============================================================
    # Verification Results
    # ============================================================

    def save_verification_result(self, result: VerificationResultModel) -> VerificationResultModel:
        sql = """
            INSERT OR REPLACE INTO verification_results (
                id, incident_id, execution_id, verification_status, summary,
                error_rate_before, error_rate_after, latency_before, latency_after,
                metrics_before_json, metrics_after_json, resolution_checks_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            result.id, result.incident_id, result.execution_id, result.verification_status,
            result.summary, result.error_rate_before, result.error_rate_after,
            result.latency_before, result.latency_after, result.metrics_before_json,
            result.metrics_after_json, result.resolution_checks_json, result.created_at
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return result

    def get_verification_result(self, incident_id: str) -> Optional[VerificationResultModel]:
        row = self._fetchone(
            "SELECT * FROM verification_results WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
            (incident_id,)
        )
        if row:
            return VerificationResultModel(**dict(row))
        return None

    # ============================================================
    # Activity Events (Audit Log)
    # ============================================================

    def append_activity(self, event: str, incident_id: str = "", actor: str = "system",
                        description: str = "", metadata: Optional[Dict] = None) -> ActivityEventModel:
        activity = ActivityEventModel(
            id=f"ACT-{uuid.uuid4().hex[:12]}",
            timestamp=self._now(),
            actor=actor,
            event=event,
            incident_id=incident_id,
            description=description,
            metadata_json=json.dumps(metadata or {})
        )
        sql = """
            INSERT INTO activity_events (id, timestamp, actor, event, incident_id, description, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            activity.id, activity.timestamp, activity.actor, activity.event,
            activity.incident_id, activity.description, activity.metadata_json
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return activity

    def list_activity(self, incident_id: str = "", limit: int = 50) -> List[ActivityEventModel]:
        sql = "SELECT * FROM activity_events WHERE 1=1"
        params = []
        if incident_id:
            sql += " AND incident_id = ?"
            params.append(incident_id)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(sql, tuple(params))
        return [ActivityEventModel(**dict(row)) for row in rows]

    # ============================================================
    # Incident Memory
    # ============================================================

    def save_incident_memory(self, memory: IncidentMemoryModel) -> IncidentMemoryModel:
        # 22 columns, 22 placeholders
        placeholders = ", ".join(["?"] * 22)
        sql = f"""
            INSERT OR REPLACE INTO incident_memory (
                id, incident_id, service, symptoms_json, timeline_json,
                root_cause, root_cause_category, supporting_evidence_json,
                blast_radius_json, remediation_json, approval_outcome,
                execution_result_json, verification_result_json, final_status,
                timestamps_json, confidence, code_paths_json, error_signatures_json,
                resolution_json, pr_id, verification_outcome, created_at
            ) VALUES ({placeholders})
        """
        params = (
            memory.id, memory.incident_id, memory.service, memory.symptoms_json,
            memory.timeline_json, memory.root_cause, memory.root_cause_category,
            memory.supporting_evidence_json, memory.blast_radius_json, memory.remediation_json,
            memory.approval_outcome, memory.execution_result_json, memory.verification_result_json,
            memory.final_status, memory.timestamps_json, memory.confidence,
            memory.code_paths_json, memory.error_signatures_json, memory.resolution_json,
            memory.pr_id, memory.verification_outcome, memory.created_at
        )
        self._execute(sql, params)
        self._get_conn().commit()
        return memory

    def get_incident_memory(self, incident_id: str) -> Optional[IncidentMemoryModel]:
        row = self._fetchone("SELECT * FROM incident_memory WHERE incident_id = ?", (incident_id,))
        if row:
            return IncidentMemoryModel(**dict(row))
        return None

    def load_all_incident_memory(self) -> List[IncidentMemoryModel]:
        rows = self._fetchall("SELECT * FROM incident_memory ORDER BY created_at DESC")
        return [IncidentMemoryModel(**dict(row)) for row in rows]

    def find_similar_incidents(self, root_cause_category: str = "", service: str = "",
                               limit: int = 10) -> List[IncidentMemoryModel]:
        sql = "SELECT * FROM incident_memory WHERE 1=1"
        params = []
        if root_cause_category:
            sql += " AND root_cause_category = ?"
            params.append(root_cause_category)
        if service:
            sql += " AND service = ?"
            params.append(service)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = self._fetchall(sql, tuple(params))
        return [IncidentMemoryModel(**dict(row)) for row in rows]

    # ============================================================
    # Idempotency Keys
    # ============================================================

    def check_idempotency(self, key: str) -> Optional[str]:
        """Check if idempotency key exists and return entity_id if found."""
        row = self._fetchone(
            "SELECT entity_id FROM idempotency_keys WHERE key = ? AND expires_at > ?",
            (key, self._now())
        )
        return row[0] if row else None

    def save_idempotency(self, key: str, entity_type: str, entity_id: str, ttl_seconds: int = 3600) -> None:
        from datetime import timedelta
        expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()
        sql = """
            INSERT OR REPLACE INTO idempotency_keys (key, entity_type, entity_id, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """
        self._execute(sql, (key, entity_type, entity_id, self._now(), expires))
        self._get_conn().commit()

    # ============================================================
    # Health / Status
    # ============================================================

    def health_check(self) -> Dict[str, Any]:
        """Check database health."""
        try:
            self._execute("SELECT 1")
            version = get_current_version(self._get_conn())
            return {
                "status": "healthy",
                "schema_version": version,
                "database": self.db_path
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "database": self.db_path
            }

    def get_stats(self) -> Dict[str, int]:
        """Get database statistics."""
        stats = {}
        tables = [
            ("projects", "projects"),
            ("incidents", "incidents"),
            ("rca_runs", "rca_runs"),
            ("code_fixes", "code_fixes"),
            ("fix_jobs", "fix_jobs"),
            ("approvals", "approvals"),
            ("pull_requests", "pull_requests"),
            ("verification_results", "verification_results"),
            ("activity_events", "activity_events"),
            ("incident_memory", "incident_memory"),
            ("analysis_sessions", "analysis_sessions"),
        ]
        for key, table in tables:
            row = self._fetchone(f"SELECT COUNT(*) as cnt FROM {table}")
            stats[key] = row["cnt"] if row else 0
        return stats


# Global singleton instance
_global_store: Optional[SQLiteStore] = None


def get_store(db_path: Optional[str] = None) -> SQLiteStore:
    """Get global SQLite store instance."""
    global _global_store
    if _global_store is None:
        _global_store = SQLiteStore(db_path)
    return _global_store


def close_store() -> None:
    """Close global store connection."""
    global _global_store
    if _global_store:
        _global_store.close()
        _global_store = None