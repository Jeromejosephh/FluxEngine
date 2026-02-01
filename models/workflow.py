"""Workflow model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Workflow:
    """Workflow model representing a workflow definition"""
    
    id: int
    name: str
    description: Optional[str]
    status: str  # 'draft', 'active', 'archived'
    created_by: int  # user_id
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True
