"""Step schemas"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any


class StepBase(BaseModel):
    """Base step schema"""
    name: str = Field(..., min_length=1, max_length=255)
    step_type: str = Field(..., pattern="^(query|transform|condition|action)$")


class StepCreate(StepBase):
    """Schema for creating a new step"""
    workflow_id: int
    config: Dict[str, Any]
    order: int = Field(..., ge=0)


class StepUpdate(BaseModel):
    """Schema for updating a step"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    step_type: Optional[str] = Field(None, pattern="^(query|transform|condition|action)$")
    config: Optional[Dict[str, Any]] = None
    order: Optional[int] = Field(None, ge=0)


class StepResponse(StepBase):
    """Schema for step response"""
    id: int
    workflow_id: int
    config: Dict[str, Any]
    order: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    is_active: bool
    
    class Config:
        from_attributes = True
