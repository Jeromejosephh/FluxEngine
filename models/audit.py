"""Audit model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class AuditEntry:
    """Audit entry model for tracking system actions"""
    
    id: int
    user_id: Optional[int]
    action: str  # 'create', 'update', 'delete', 'login', etc.
    entity_type: str  # 'user', 'table', 'workflow', 'step'
    entity_id: Optional[int]
    details: Optional[str]  # JSON string of additional details
    ip_address: Optional[str]
    timestamp: Optional[datetime] = None
