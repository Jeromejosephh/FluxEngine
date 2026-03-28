"""Workflow template model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class WorkflowTemplate:
    id: int
    name: str
    description: Optional[str]
    tags: str          # JSON array string e.g. '["etl", "reporting"]'
    step_configs: str  # JSON array of step definition dicts
    created_by: int
    created_at: datetime
    updated_at: datetime
    is_active: bool
