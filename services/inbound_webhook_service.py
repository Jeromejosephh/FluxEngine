"""Inbound webhook service"""
import secrets
import json
from typing import Any, Dict, List, Union

from models.inbound_webhook import InboundWebhook
from services.duckdb_service import DuckDBService
from utils.exceptions import ValidationException, NotFoundException, DatabaseException


class InboundWebhookService:

    def __init__(self):
        self.db = DuckDBService()

    def create_webhook(self, table_id: int, user_id: int,
                       description: str = None,
                       trigger_workflow_id: int = None) -> InboundWebhook:
        table = self.db.get_table_by_id(table_id)
        if not table:
            raise NotFoundException(f"Table {table_id} not found")

        existing = self.db.get_inbound_webhook_by_table(table_id)
        if existing:
            raise ValidationException("This table already has an inbound webhook. Delete it first.")

        if trigger_workflow_id is not None:
            wf = self.db.get_workflow_by_id(trigger_workflow_id)
            if not wf:
                raise NotFoundException(f"Workflow {trigger_workflow_id} not found")

        token = secrets.token_urlsafe(32)
        return self.db.create_inbound_webhook(table_id, token, description, trigger_workflow_id, user_id)

    def get_webhook_for_table(self, table_id: int) -> InboundWebhook:
        webhook = self.db.get_inbound_webhook_by_table(table_id)
        if not webhook:
            raise NotFoundException(f"No inbound webhook for table {table_id}")
        return webhook

    def update_webhook(self, table_id: int, **kwargs) -> InboundWebhook:
        webhook = self.get_webhook_for_table(table_id)
        updated = self.db.update_inbound_webhook(webhook.id, **kwargs)
        if not updated:
            raise NotFoundException("Webhook not found")
        return updated

    def rotate_token(self, table_id: int) -> InboundWebhook:
        webhook = self.get_webhook_for_table(table_id)
        new_token = secrets.token_urlsafe(32)
        updated = self.db.update_inbound_webhook(webhook.id, token=new_token)
        return updated

    def delete_webhook(self, table_id: int) -> None:
        webhook = self.get_webhook_for_table(table_id)
        self.db.delete_inbound_webhook(webhook.id)

    def receive(self, token: str, payload: Union[Dict, List]) -> Dict[str, Any]:
        webhook = self.db.get_inbound_webhook_by_token(token)
        if not webhook:
            raise NotFoundException("Invalid webhook token")

        if not webhook.is_enabled:
            raise ValidationException("This webhook is disabled")

        table = self.db.get_table_by_id(webhook.table_id)
        if not table:
            raise NotFoundException("Table not found")

        schema = json.loads(table.schema_definition)
        allowed_columns = {col["name"] for col in schema.get("columns", [])}

        rows = payload if isinstance(payload, list) else [payload]
        cleaned = []
        for row in rows:
            cleaned.append({k: v for k, v in row.items() if k in allowed_columns})

        if not cleaned:
            return {"received": True, "inserted": 0, "workflow_triggered": False}

        inserted = self.db.insert_rows(table, cleaned)

        self.db.update_inbound_webhook_last_triggered(webhook.id)

        workflow_triggered = False
        if webhook.trigger_workflow_id:
            try:
                from services.execution_service import ExecutionService
                from services.duckdb_service import DuckDBService
                exec_service = ExecutionService()
                result = exec_service.run_workflow(webhook.trigger_workflow_id, user_id=webhook.created_by)
                DuckDBService().save_execution(result, webhook.created_by)
                workflow_triggered = True
            except Exception:
                pass

        return {"received": True, "inserted": inserted, "workflow_triggered": workflow_triggered}
