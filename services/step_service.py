"""Step management service"""
import json
from typing import List, Dict, Any

from schemas.step import StepCreate
from models.step import Step
from services.duckdb_service import DuckDBService
from utils.exceptions import ValidationException, NotFoundException, DatabaseException


class StepService:
    """Service for workflow step management"""

    # Required config keys per step type
    REQUIRED_CONFIG_KEYS = {
        "query": ["table_id"],
        "transform": [],   # select_columns and/or filter are optional
        "condition": [],
        "action": ["webhook_url"],
    }

    def __init__(self):
        self.db_service = DuckDBService()

    def validate_step_config(self, step_type: str, config: Dict[str, Any]) -> None:
        """
        Validate that the step config contains required keys for its type.

        Raises:
            ValidationException: If config is invalid.
        """
        required = self.REQUIRED_CONFIG_KEYS.get(step_type, [])
        for key in required:
            if key not in config:
                raise ValidationException(
                    f"Step type '{step_type}' requires config key '{key}'"
                )

        if step_type == "transform":
            has_select = "select_columns" in config
            has_filter = "filter" in config
            if not has_select and not has_filter:
                raise ValidationException(
                    "Transform step config must include 'select_columns' and/or 'filter'"
                )

            if has_filter:
                f = config["filter"]
                for key in ("column", "op", "value"):
                    if key not in f:
                        raise ValidationException(
                            f"Transform filter must include 'column', 'op', and 'value'. Missing: '{key}'"
                        )
                allowed_ops = {"eq", "ne", "gt", "gte", "lt", "lte"}
                if f["op"] not in allowed_ops:
                    raise ValidationException(
                        f"Transform filter op '{f['op']}' not supported. Use: {', '.join(sorted(allowed_ops))}"
                    )

        if step_type == "action":
            webhook_url = config.get("webhook_url", "")
            if not isinstance(webhook_url, str) or not webhook_url.startswith(("http://", "https://")):
                raise ValidationException(
                    "Action step 'webhook_url' must be a valid http:// or https:// URL"
                )
            timeout = config.get("timeout_seconds")
            if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
                raise ValidationException(
                    "Action step 'timeout_seconds' must be a positive number"
                )
            headers = config.get("headers")
            if headers is not None and not isinstance(headers, dict):
                raise ValidationException(
                    "Action step 'headers' must be a dict of string key-value pairs"
                )

    def create_step(self, workflow_id: int, data: StepCreate, user_id: int) -> Step:
        """
        Create a new step for a workflow.

        Raises:
            NotFoundException: If the workflow does not exist.
            ValidationException: If config is invalid.
            DatabaseException: On database errors.
        """
        # Verify workflow exists
        workflow = self.db_service.get_workflow_by_id(workflow_id)
        if not workflow:
            raise NotFoundException(f"Workflow with ID {workflow_id} not found")

        # Validate config
        self.validate_step_config(data.step_type, data.config)

        try:
            return self.db_service.create_step(
                workflow_id=workflow_id,
                name=data.name,
                step_type=data.step_type,
                config=json.dumps(data.config),
                order=data.order
            )
        except Exception as e:
            raise DatabaseException(f"Failed to create step: {str(e)}")

    def get_steps_for_workflow(self, workflow_id: int) -> List[Step]:
        """
        Get all steps for a workflow ordered by execution order.

        Raises:
            NotFoundException: If the workflow does not exist.
        """
        workflow = self.db_service.get_workflow_by_id(workflow_id)
        if not workflow:
            raise NotFoundException(f"Workflow with ID {workflow_id} not found")
        return self.db_service.get_steps_by_workflow(workflow_id)
