"""Table schemas"""
from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Dict, Any


class TableBase(BaseModel):
    """Base table schema"""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class TableCreate(TableBase):
    """Schema for creating a new table"""
    schema_definition: Dict[str, Any]  # Will be converted to JSON string


class TableUpdate(BaseModel):
    """Schema for updating a table"""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    schema_definition: Optional[Dict[str, Any]] = None


class TableResponse(TableBase):
    """Schema for table response"""
    id: int
    schema_definition: Dict[str, Any]
    created_by: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    is_active: bool
    
    class Config:
        from_attributes = True
