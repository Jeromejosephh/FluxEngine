"""Analytics schemas"""
from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class WorkflowAnalytics(BaseModel):
    """Aggregated execution stats for a workflow"""
    workflow_id: int
    workflow_name: str
    total_runs: int
    successful_runs: int
    failed_runs: int
    success_rate: float             # 0.0 – 1.0
    avg_steps_per_run: float
    avg_output_rows: float          # avg final_output_count across successful runs
    first_run_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    runs_last_7_days: int
    runs_last_30_days: int
