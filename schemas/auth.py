"""Authentication schemas"""
from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    """JWT token response schema"""
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Token payload data"""
    user_id: Optional[int] = None
    email: Optional[str] = None
    role: Optional[str] = None
