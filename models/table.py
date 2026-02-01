"""Table model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class Table:
    """Table model representing a data table in the system"""
    
    id: int
    name: str
    description: Optional[str]
    schema_definition: str  # JSON string of column definitions
    created_by: int  # user_id
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    is_active: bool = True
