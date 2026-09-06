"""
ExecutionResult schemas
"""
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum

class ExecutionStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"

class ExecutionResult(BaseModel):
    execution_id: str
    approval_id: str
    incident_id: str
    action: str
    target_resource: str
    start_time: str
    end_time: str
    status: ExecutionStatus
    cloud_operation_id: Optional[str] = None
    before_state: Optional[dict] = None
    after_state: Optional[dict] = None
    error_message: Optional[str] = None
    rollback_available: bool = False
