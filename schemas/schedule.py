"""Schedule schemas"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class ScheduleCreate(BaseModel):
    """Schema for creating or replacing a workflow schedule"""
    cron_expr: str = Field(..., description="5-field cron expression, e.g. '0 * * * *'")
    is_enabled: bool = True


class ScheduleUpdate(BaseModel):
    """Schema for partially updating a schedule"""
    cron_expr: Optional[str] = None
    is_enabled: Optional[bool] = None


class ScheduleResponse(BaseModel):
    """Schedule response"""
    id: int
    workflow_id: int
    cron_expr: str
    is_enabled: bool
    created_by: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None

    class Config:
        from_attributes = True
