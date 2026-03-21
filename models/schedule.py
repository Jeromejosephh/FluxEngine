"""Schedule model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Schedule:
    """Persisted cron schedule for a workflow"""
    id: int
    workflow_id: int
    cron_expr: str          # standard 5-field cron (e.g. "0 * * * *")
    is_enabled: bool
    created_by: int         # user who created the schedule
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
