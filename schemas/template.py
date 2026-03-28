"""Workflow template Pydantic schemas"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, field_validator
from datetime import datetime


class TemplateStepConfig(BaseModel):
    """A single step definition stored inside a template"""
    name: str
    step_type: str
    config: Dict[str, Any]
    order: int

    @field_validator("step_type")
    @classmethod
    def validate_step_type(cls, v: str) -> str:
        allowed = {"query", "transform", "condition", "action"}
        if v not in allowed:
            raise ValueError(f"step_type must be one of {allowed}")
        return v

    @field_validator("order")
    @classmethod
    def validate_order(cls, v: int) -> int:
        if v < 0:
            raise ValueError("order must be >= 0")
        return v


class TemplateCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tags: Optional[List[str]] = []
    step_configs: List[TemplateStepConfig]

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty")
        if len(v) > 255:
            raise ValueError("name cannot exceed 255 characters")
        return v

    @field_validator("step_configs")
    @classmethod
    def validate_step_configs(cls, v: List[TemplateStepConfig]) -> List[TemplateStepConfig]:
        if not v:
            raise ValueError("step_configs must contain at least one step")
        return v


class TemplateResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    tags: List[str]
    step_configs: List[TemplateStepConfig]
    created_by: int
    created_at: datetime
    updated_at: datetime
    is_active: bool

    model_config = {"from_attributes": True}


class TemplateClone(BaseModel):
    """Request body for cloning a template into a real workflow"""
    name: str
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("name cannot be empty")
        if len(v) > 255:
            raise ValueError("name cannot exceed 255 characters")
        return v
