"""Workflow management routes"""
import json
from fastapi import APIRouter, Depends, HTTPException, Request, status
from typing import List
from utils.limiter import limiter

from schemas.workflow import WorkflowCreate, WorkflowUpdate, WorkflowResponse
from schemas.step import StepCreate, StepResponse
from schemas.execution import ExecutionResult, ExecutionSummary
from schemas.schedule import ScheduleCreate, ScheduleUpdate, ScheduleResponse
from schemas.analytics import WorkflowAnalytics
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
@limiter.limit("10/minute")
async def run_workflow(
    request: Request,
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


@router.get("/{workflow_id}/analytics", response_model=WorkflowAnalytics)
async def get_workflow_analytics(
    workflow_id: int,
    token: str = Depends(oauth2_scheme)
):
    """Return aggregated execution stats for a workflow."""
    await get_current_user_from_token(token)
    from services.duckdb_service import DuckDBService
    db = DuckDBService()
    analytics = db.get_workflow_analytics(workflow_id)
    if analytics is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Workflow {workflow_id} not found")
    return analytics


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


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------

@router.post("/{workflow_id}/schedule", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    workflow_id: int,
    data: ScheduleCreate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """
    Set a cron schedule for a workflow. Replaces any existing schedule.
    cron_expr is a standard 5-field cron string, e.g. '0 * * * *'.
    """
    user = await get_current_user_from_token(token)
    workflow_service = WorkflowService()

    try:
        workflow_service.get_workflow_by_id(workflow_id)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)

    from services.scheduler_service import validate_cron, add_or_replace_job, remove_job, _compute_next_run
    from services.duckdb_service import DuckDBService

    try:
        validate_cron(data.cron_expr)
    except ValidationException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)

    db = DuckDBService()
    next_run = _compute_next_run(data.cron_expr) if data.is_enabled else None
    existing = db.get_schedule_by_workflow(workflow_id)

    if existing:
        schedule = db.update_schedule(
            workflow_id,
            cron_expr=data.cron_expr,
            is_enabled=data.is_enabled,
            next_run_at=next_run,
        )
    else:
        schedule = db.create_schedule(
            workflow_id=workflow_id,
            cron_expr=data.cron_expr,
            is_enabled=data.is_enabled,
            created_by=user.id,
            next_run_at=next_run,
        )

    if data.is_enabled:
        add_or_replace_job(workflow_id, data.cron_expr, user.id)
    else:
        remove_job(workflow_id)

    audit_service = AuditService()
    audit_service.log_action(
        user_id=user.id,
        action="schedule",
        entity_type="workflow",
        entity_id=workflow_id,
        details=f"Set schedule '{data.cron_expr}' (enabled={data.is_enabled})"
    )
    return schedule


@router.get("/{workflow_id}/schedule", response_model=ScheduleResponse)
async def get_schedule(
    workflow_id: int,
    token: str = Depends(oauth2_scheme)
):
    """Get the current schedule for a workflow."""
    await get_current_user_from_token(token)
    workflow_service = WorkflowService()

    try:
        workflow_service.get_workflow_by_id(workflow_id)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)

    from services.duckdb_service import DuckDBService
    schedule = DuckDBService().get_schedule_by_workflow(workflow_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No schedule found for this workflow")
    return schedule


@router.patch("/{workflow_id}/schedule", response_model=ScheduleResponse)
async def update_schedule(
    workflow_id: int,
    data: ScheduleUpdate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """Partially update a schedule (change cron expression or enable/disable)."""
    user = await get_current_user_from_token(token)
    workflow_service = WorkflowService()

    try:
        workflow_service.get_workflow_by_id(workflow_id)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)

    from services.scheduler_service import validate_cron, add_or_replace_job, remove_job, _compute_next_run
    from services.duckdb_service import DuckDBService

    db = DuckDBService()
    existing = db.get_schedule_by_workflow(workflow_id)
    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No schedule found for this workflow")

    if data.cron_expr is not None:
        try:
            validate_cron(data.cron_expr)
        except ValidationException as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)

    new_cron = data.cron_expr if data.cron_expr is not None else existing.cron_expr
    new_enabled = data.is_enabled if data.is_enabled is not None else existing.is_enabled
    next_run = _compute_next_run(new_cron) if new_enabled else None

    schedule = db.update_schedule(
        workflow_id,
        cron_expr=new_cron,
        is_enabled=new_enabled,
        next_run_at=next_run,
    )

    if new_enabled:
        add_or_replace_job(workflow_id, new_cron, user.id)
    else:
        remove_job(workflow_id)

    return schedule


@router.delete("/{workflow_id}/schedule", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    workflow_id: int,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """Remove the schedule from a workflow."""
    user = await get_current_user_from_token(token)
    workflow_service = WorkflowService()

    try:
        workflow_service.get_workflow_by_id(workflow_id)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)

    from services.scheduler_service import remove_job
    from services.duckdb_service import DuckDBService

    deleted = DuckDBService().delete_schedule(workflow_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No schedule found for this workflow")

    remove_job(workflow_id)

    AuditService().log_action(
        user_id=user.id,
        action="delete_schedule",
        entity_type="workflow",
        entity_id=workflow_id,
        details=f"Removed schedule from workflow {workflow_id}"
    )
    return None
