"""Execution result schemas"""
from pydantic import BaseModel
from datetime import datetime
from typing import Any, List, Optional


class StepResult(BaseModel):
    """Result of a single step execution"""
    step_id: int
    step_name: str
    step_type: str
    success: bool
    rows_out: int = 0
    output: Optional[Any] = None
    error: Optional[str] = None


class ExecutionResult(BaseModel):
    """Full result of running a workflow"""
    workflow_id: int
    workflow_name: str
    success: bool
    executed_at: datetime
    steps: List[StepResult]
    final_output: Optional[Any] = None
    error: Optional[str] = None


class StepSummary(BaseModel):
    """Persisted summary of a single step (no output row data)"""
    step_id: int
    step_name: str
    step_type: str
    success: bool
    rows_out: int
    error: Optional[str] = None


class ExecutionSummary(BaseModel):
    """Response schema for a persisted execution record"""
    id: int
    workflow_id: int
    workflow_name: str
    success: bool
    executed_at: datetime
    executed_by: int
    error: Optional[str]
    step_count: int
    steps: List[StepSummary]
    final_output_count: Optional[int]
