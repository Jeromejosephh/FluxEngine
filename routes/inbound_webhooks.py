"""Inbound webhook routes"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import Any, Dict, List, Union

from schemas.inbound_webhook import (
    InboundWebhookCreate, InboundWebhookUpdate,
    InboundWebhookResponse, WebhookReceiveResponse,
)
from routes.auth import oauth2_scheme
from utils.security import require_role
from services.auth_service import AuthService
from services.inbound_webhook_service import InboundWebhookService
from utils.exceptions import NotFoundException, ValidationException
from utils.limiter import limiter

management_router = APIRouter()
public_router = APIRouter()


async def get_current_user_from_token(token: str):
    auth_service = AuthService()
    from fastapi import HTTPException, status
    try:
        return auth_service.get_current_user(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


def _to_response(webhook) -> InboundWebhookResponse:
    return InboundWebhookResponse(
        id=webhook.id,
        table_id=webhook.table_id,
        token=webhook.token,
        description=webhook.description,
        is_enabled=webhook.is_enabled,
        trigger_workflow_id=webhook.trigger_workflow_id,
        created_by=webhook.created_by,
        created_at=webhook.created_at,
        updated_at=webhook.updated_at,
        last_triggered_at=webhook.last_triggered_at,
    )


# ---------------------------------------------------------------------------
# Management endpoints (authenticated)
# ---------------------------------------------------------------------------

@management_router.post("/tables/{table_id}", response_model=InboundWebhookResponse, status_code=201)
async def create_webhook(
    table_id: int,
    data: InboundWebhookCreate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"])),
):
    user = await get_current_user_from_token(token)
    service = InboundWebhookService()
    try:
        webhook = service.create_webhook(
            table_id=table_id,
            user_id=user.id,
            description=data.description,
            trigger_workflow_id=data.trigger_workflow_id,
        )
        return _to_response(webhook)
    except NotFoundException as e:
        raise HTTPException(status_code=404, detail=e.detail)
    except ValidationException as e:
        raise HTTPException(status_code=422, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@management_router.get("/tables/{table_id}", response_model=InboundWebhookResponse)
async def get_webhook(
    table_id: int,
    token: str = Depends(oauth2_scheme),
):
    await get_current_user_from_token(token)
    service = InboundWebhookService()
    try:
        return _to_response(service.get_webhook_for_table(table_id))
    except NotFoundException as e:
        raise HTTPException(status_code=404, detail=e.detail)


@management_router.patch("/tables/{table_id}", response_model=InboundWebhookResponse)
async def update_webhook(
    table_id: int,
    data: InboundWebhookUpdate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"])),
):
    await get_current_user_from_token(token)
    service = InboundWebhookService()
    try:
        kwargs = {k: v for k, v in data.model_dump().items() if v is not None}
        return _to_response(service.update_webhook(table_id, **kwargs))
    except NotFoundException as e:
        raise HTTPException(status_code=404, detail=e.detail)


@management_router.post("/tables/{table_id}/rotate", response_model=InboundWebhookResponse)
async def rotate_token(
    table_id: int,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"])),
):
    await get_current_user_from_token(token)
    service = InboundWebhookService()
    try:
        return _to_response(service.rotate_token(table_id))
    except NotFoundException as e:
        raise HTTPException(status_code=404, detail=e.detail)


@management_router.delete("/tables/{table_id}", status_code=204)
async def delete_webhook(
    table_id: int,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin"])),
):
    await get_current_user_from_token(token)
    service = InboundWebhookService()
    try:
        service.delete_webhook(table_id)
    except NotFoundException as e:
        raise HTTPException(status_code=404, detail=e.detail)


# ---------------------------------------------------------------------------
# Public receive endpoint (no auth - token in URL is the credential)
# ---------------------------------------------------------------------------

@public_router.post("/inbound/{token}", response_model=WebhookReceiveResponse)
@limiter.limit("60/minute")
async def receive_webhook(
    request: Request,
    token: str,
    payload: Union[Dict[str, Any], List[Dict[str, Any]]],
):
    service = InboundWebhookService()
    try:
        result = service.receive(token, payload)
        return result
    except NotFoundException:
        raise HTTPException(status_code=404, detail="Webhook not found")
    except ValidationException as e:
        raise HTTPException(status_code=422, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
