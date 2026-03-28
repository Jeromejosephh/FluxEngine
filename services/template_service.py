"""Workflow template service"""
import json
from typing import List

from schemas.template import TemplateCreate
from models.template import WorkflowTemplate
from services.duckdb_service import DuckDBService
from services.step_service import StepService
from utils.exceptions import ValidationException, NotFoundException, DatabaseException


class TemplateService:
    """Service for workflow template management"""

    def __init__(self):
        self.db_service = DuckDBService()
        self.step_service = StepService()

    def create_template(self, data: TemplateCreate, user_id: int) -> WorkflowTemplate:
        """
        Create a new workflow template.

        Validates each step config using StepService rules, then persists.

        Raises:
            ValidationException: Duplicate name or invalid step config.
            DatabaseException: On database errors.
        """
        # Validate each step config
        for i, step in enumerate(data.step_configs):
            try:
                self.step_service.validate_step_config(step.step_type, step.config)
            except ValidationException as e:
                raise ValidationException(f"Step {i} ({step.name!r}): {e.detail}")

        tags_json = json.dumps(data.tags or [])
        step_configs_json = json.dumps([s.model_dump() for s in data.step_configs])

        try:
            return self.db_service.create_template(
                name=data.name,
                description=data.description,
                tags=tags_json,
                step_configs=step_configs_json,
                created_by=user_id,
            )
        except Exception as e:
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                raise ValidationException(f"Template with name '{data.name}' already exists")
            raise DatabaseException(f"Failed to create template: {str(e)}")

    def get_template_by_id(self, template_id: int) -> WorkflowTemplate:
        """
        Get a template by ID.

        Raises:
            NotFoundException: If template does not exist.
        """
        template = self.db_service.get_template_by_id(template_id)
        if not template:
            raise NotFoundException(f"Template with ID {template_id} not found")
        return template

    def get_all_templates(self, skip: int = 0, limit: int = 100) -> List[WorkflowTemplate]:
        """Return all active templates with pagination."""
        return self.db_service.get_all_templates(skip=skip, limit=limit)

    def delete_template(self, template_id: int, user_id: int) -> None:
        """
        Soft delete a template.

        Raises:
            NotFoundException: If template does not exist.
        """
        self.get_template_by_id(template_id)
        self.db_service.soft_delete_template(template_id)
