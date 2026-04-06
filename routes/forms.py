"""Public form routes — no authentication required"""
import json
from fastapi import APIRouter, HTTPException
from typing import Any, Dict

from services.duckdb_service import DuckDBService

router = APIRouter()


@router.get("/{token}")
async def get_form_schema(token: str) -> Dict[str, Any]:
    """Return table name and column schema for a given webhook token. Public, no auth."""
    db = DuckDBService()
    webhook = db.get_inbound_webhook_by_token(token)
    if not webhook or not webhook.is_enabled:
        raise HTTPException(status_code=404, detail="Form not found")

    table = db.get_table_by_id(webhook.table_id)
    if not table:
        raise HTTPException(status_code=404, detail="Table not found")

    schema = json.loads(table.schema_definition)
    return {
        "table_name": table.name,
        "description": table.description,
        "columns": schema.get("columns", []),
        "token": token,
    }
