"""Workflow schemas"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional


class WorkflowBase(BaseModel):
    """Base workflow schema"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class WorkflowCreate(WorkflowBase):
    """Schema for creating a new workflow"""
    status: str = Field(default="draft", pattern="^(draft|active|archived)$")


class WorkflowUpdate(BaseModel):
    """Schema for updating a workflow"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(draft|active|archived)$")


class WorkflowResponse(WorkflowBase):
    """Schema for workflow response"""
    id: int
    status: str
    created_by: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    is_active: bool
    
    class Config:
        from_attributes = True
