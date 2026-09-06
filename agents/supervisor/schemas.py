"""Supervisor schemas"""
from typing import List, Optional
from pydantic import BaseModel, Field

class InvestigationPlan(BaseModel):
    plan: List[str] = Field(..., description="Ordered list of investigation tasks")
    reasoning: str = Field(..., description="Why these agents/tasks were selected")
    skip_agents: List[str] = Field(default_factory=list, description="Agents not needed and why")
