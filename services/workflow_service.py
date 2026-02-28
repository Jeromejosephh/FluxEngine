"""Workflow management service"""
from typing import List, Optional

from schemas.workflow import WorkflowCreate, WorkflowUpdate
from models.workflow import Workflow
from services.duckdb_service import DuckDBService
from utils.exceptions import ValidationException, NotFoundException, DatabaseException


class WorkflowService:
    """Service for workflow management operations"""

    def __init__(self):
        self.db_service = DuckDBService()

    def create_workflow(self, data: WorkflowCreate, user_id: int) -> Workflow:
        """
        Create a new workflow.

        Raises:
            ValidationException: If a workflow with the same name already exists.
            DatabaseException: On database errors.
        """
        try:
            return self.db_service.create_workflow(
                name=data.name,
                description=data.description,
                status=data.status,
                created_by=user_id
            )
        except Exception as e:
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                raise ValidationException(f"Workflow with name '{data.name}' already exists")
            raise DatabaseException(f"Failed to create workflow: {str(e)}")

    def get_workflow_by_id(self, workflow_id: int) -> Workflow:
        """
        Get workflow by ID.

        Raises:
            NotFoundException: If workflow does not exist.
        """
        workflow = self.db_service.get_workflow_by_id(workflow_id)
        if not workflow:
            raise NotFoundException(f"Workflow with ID {workflow_id} not found")
        return workflow

    def get_all_workflows(self, skip: int = 0, limit: int = 100) -> List[Workflow]:
        """Return all active workflows with pagination."""
        return self.db_service.get_all_workflows(skip=skip, limit=limit)

    def update_workflow(self, workflow_id: int, updates: WorkflowUpdate, user_id: int) -> Workflow:
        """
        Update workflow fields.

        Raises:
            NotFoundException: If workflow does not exist.
            DatabaseException: On database errors.
        """
        # Verify exists first
        self.get_workflow_by_id(workflow_id)

        try:
            workflow = self.db_service.update_workflow(
                workflow_id=workflow_id,
                name=updates.name,
                description=updates.description,
                status=updates.status
            )
            if not workflow:
                raise NotFoundException(f"Workflow with ID {workflow_id} not found")
            return workflow
        except (NotFoundException, ValidationException):
            raise
        except Exception as e:
            raise DatabaseException(f"Failed to update workflow: {str(e)}")

    def delete_workflow(self, workflow_id: int, user_id: int) -> None:
        """
        Soft delete a workflow.

        Raises:
            NotFoundException: If workflow does not exist.
        """
        self.get_workflow_by_id(workflow_id)
        self.db_service.soft_delete_workflow(workflow_id)
