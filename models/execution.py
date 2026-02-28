"""Execution model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Execution:
    """Persisted record of a single workflow run"""
    id: int
    workflow_id: int
    workflow_name: str
    success: bool
    executed_at: datetime
    executed_by: int
    error: Optional[str]
    step_count: int
    steps_json: str              # JSON array of step summaries (no output row data)
    final_output_count: Optional[int]
    created_at: Optional[datetime] = None
