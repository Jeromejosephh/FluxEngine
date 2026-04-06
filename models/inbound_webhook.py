"""Inbound webhook model"""
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class InboundWebhook:
    id: int
    table_id: int
    token: str
    description: Optional[str]
    is_enabled: bool
    trigger_workflow_id: Optional[int]
    created_by: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_triggered_at: Optional[datetime] = None
