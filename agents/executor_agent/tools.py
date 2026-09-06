"""Executor helper - dispatch allowlisted actions"""
from tools.remediation_tools import rollback_cloud_run_revision, shift_cloud_run_traffic, scale_cloud_run_service

DISPATCH = {
    "cloud_run_rollback": rollback_cloud_run_revision,
    "cloud_run_shift_traffic": shift_cloud_run_traffic,
    "cloud_run_scale_within_limits": scale_cloud_run_service,
}
