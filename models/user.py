"""User model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class User:
    """User model representing a system user"""
    
    id: int
    email: str
    hashed_password: str
    full_name: str
    role: str  # 'admin' or 'editor'
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @property
    def is_admin(self) -> bool:
        """Check if user has admin role"""
        return self.role == "admin"
    
    @property
    def is_editor(self) -> bool:
        """Check if user has editor role"""
        return self.role == "editor"
