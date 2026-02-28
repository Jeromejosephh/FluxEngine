"""Workflow management routes"""
import json
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from schemas.workflow import WorkflowCreate, WorkflowUpdate, WorkflowResponse
from schemas.step import StepCreate, StepResponse
from schemas.execution import ExecutionResult, ExecutionSummary
from routes.auth import oauth2_scheme
from utils.security import require_role
from services.auth_service import AuthService
from services.workflow_service import WorkflowService
from services.step_service import StepService
from services.execution_service import ExecutionService
from services.audit_service import AuditService
from utils.exceptions import ValidationException, NotFoundException, DatabaseException

router = APIRouter()


async def get_current_user_from_token(token: str):
    """Helper to get current user from token"""
    auth_service = AuthService()
    try:
        return auth_service.get_current_user(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


def _step_to_response(step) -> StepResponse:
    """Convert a Step model to StepResponse, deserialising the config JSON."""
    return StepResponse(
        id=step.id,
        workflow_id=step.workflow_id,
        name=step.name,
        step_type=step.step_type,
        config=json.loads(step.config),
        order=step.order,
        created_at=step.created_at,
        updated_at=step.updated_at,
        is_active=step.is_active
    )


# ---------------------------------------------------------------------------
# Workflow CRUD
# ---------------------------------------------------------------------------

@router.get("/", response_model=List[WorkflowResponse])
async def list_workflows(
    skip: int = 0,
    limit: int = 100,
    token: str = Depends(oauth2_scheme)
):
    """List all workflows"""
    await get_current_user_from_token(token)
    workflow_service = WorkflowService()
    try:
        return workflow_service.get_all_workflows(skip=skip, limit=limit)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{workflow_id}", response_model=WorkflowResponse)
async def get_workflow(
    workflow_id: int,
    token: str = Depends(oauth2_scheme)
):
    """Get workflow by ID"""
    await get_current_user_from_token(token)
    workflow_service = WorkflowService()
    try:
        return workflow_service.get_workflow_by_id(workflow_id)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/", response_model=WorkflowResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow(
    workflow_data: WorkflowCreate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """Create a new workflow (requires admin or editor role)"""
    user = await get_current_user_from_token(token)
    workflow_service = WorkflowService()
    audit_service = AuditService()

    try:
        workflow = workflow_service.create_workflow(workflow_data, user_id=user.id)
        audit_service.log_action(
            user_id=user.id,
            action="create",
            entity_type="workflow",
            entity_id=workflow.id,
            details=f"Created workflow: {workflow.name}"
        )
        return workflow
    except ValidationException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
    except DatabaseException as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.put("/{workflow_id}", response_model=WorkflowResponse)
async def update_workflow(
    workflow_id: int,
    workflow_data: WorkflowUpdate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """Update an existing workflow (requires admin or editor role)"""
    user = await get_current_user_from_token(token)
    workflow_service = WorkflowService()
    audit_service = AuditService()

    try:
        workflow = workflow_service.update_workflow(workflow_id, workflow_data, user_id=user.id)
        audit_service.log_action(
            user_id=user.id,
            action="update",
            entity_type="workflow",
            entity_id=workflow.id,
            details=f"Updated workflow: {workflow.name}"
        )
        return workflow
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)
    except ValidationException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.delete("/{workflow_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_workflow(
    workflow_id: int,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin"]))
):
    """Delete a workflow — soft delete (requires admin role)"""
    user = await get_current_user_from_token(token)
    workflow_service = WorkflowService()
    audit_service = AuditService()

    try:
        workflow = workflow_service.get_workflow_by_id(workflow_id)
        workflow_service.delete_workflow(workflow_id, user_id=user.id)
        audit_service.log_action(
            user_id=user.id,
            action="delete",
            entity_type="workflow",
            entity_id=workflow_id,
            details=f"Deleted workflow: {workflow.name}"
        )
        return None
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

@router.post("/{workflow_id}/steps", response_model=StepResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow_step(
    workflow_id: int,
    step_data: StepCreate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """Add a step to a workflow (requires admin or editor role)"""
    user = await get_current_user_from_token(token)
    step_service = StepService()
    audit_service = AuditService()

    try:
        step = step_service.create_step(workflow_id, step_data, user_id=user.id)
        audit_service.log_action(
            user_id=user.id,
            action="create",
            entity_type="step",
            entity_id=step.id,
            details=f"Added step '{step.name}' to workflow {workflow_id}"
        )
        return _step_to_response(step)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)
    except ValidationException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
    except DatabaseException as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{workflow_id}/steps", response_model=List[StepResponse])
async def list_workflow_steps(
    workflow_id: int,
    token: str = Depends(oauth2_scheme)
):
    """List all steps in a workflow ordered by execution order"""
    await get_current_user_from_token(token)
    step_service = StepService()

    try:
        steps = step_service.get_steps_for_workflow(workflow_id)
        return [_step_to_response(s) for s in steps]
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

@router.post("/{workflow_id}/run", response_model=ExecutionResult)
async def run_workflow(
    workflow_id: int,
    token: str = Depends(oauth2_scheme)
):
    """
    Execute a workflow and return per-step results plus the final output.
    The workflow must have status 'active'.
    """
    user = await get_current_user_from_token(token)
    execution_service = ExecutionService()
    audit_service = AuditService()

    try:
        result = execution_service.run_workflow(workflow_id, user_id=user.id)

        from services.duckdb_service import DuckDBService
        DuckDBService().save_execution(result, user.id)

        audit_service.log_action(
            user_id=user.id,
            action="run",
            entity_type="workflow",
            entity_id=workflow_id,
            details=f"Ran workflow {workflow_id} — success: {result.success}"
        )
        return result
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)
    except ValidationException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.get("/{workflow_id}/runs", response_model=List[ExecutionSummary])
async def list_runs(
    workflow_id: int,
    skip: int = 0,
    limit: int = 50,
    token: str = Depends(oauth2_scheme)
):
    """List execution history for a workflow, newest first."""
    await get_current_user_from_token(token)
    workflow_service = WorkflowService()

    try:
        workflow_service.get_workflow_by_id(workflow_id)

        import json
        from services.duckdb_service import DuckDBService
        from schemas.execution import StepSummary
        db = DuckDBService()
        executions = db.get_executions_for_workflow(workflow_id, skip=skip, limit=limit)

        return [
            ExecutionSummary(
                id=e.id,
                workflow_id=e.workflow_id,
                workflow_name=e.workflow_name,
                success=e.success,
                executed_at=e.executed_at,
                executed_by=e.executed_by,
                error=e.error,
                step_count=e.step_count,
                steps=[StepSummary(**s) for s in json.loads(e.steps_json)],
                final_output_count=e.final_output_count,
            )
            for e in executions
        ]

    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
