"""Step model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Step:
    """Step model representing a workflow step"""
    
    id: int
    workflow_id: int
    name: str
    step_type: str  # 'query', 'transform', 'condition', 'action'
    config: str  # JSON string of step configuration
    order: int  # execution order
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True
