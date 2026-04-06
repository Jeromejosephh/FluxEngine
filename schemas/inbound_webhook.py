"""Inbound webhook Pydantic schemas"""
from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class InboundWebhookCreate(BaseModel):
    description: Optional[str] = None
    trigger_workflow_id: Optional[int] = None


class InboundWebhookUpdate(BaseModel):
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    trigger_workflow_id: Optional[int] = None


class InboundWebhookResponse(BaseModel):
    id: int
    table_id: int
    token: str
    description: Optional[str]
    is_enabled: bool
    trigger_workflow_id: Optional[int]
    created_by: int
    created_at: Optional[datetime]
    updated_at: Optional[datetime]
    last_triggered_at: Optional[datetime]

    model_config = {"from_attributes": True}


class WebhookReceiveResponse(BaseModel):
    received: bool
    inserted: int
    workflow_triggered: bool
