"""Workflow template routes"""
import json
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from schemas.template import TemplateCreate, TemplateResponse, TemplateStepConfig, TemplateClone
from schemas.workflow import WorkflowCreate, WorkflowResponse
from schemas.step import StepCreate, StepResponse
from routes.auth import oauth2_scheme
from utils.security import require_role
from services.auth_service import AuthService
from services.template_service import TemplateService
from services.workflow_service import WorkflowService
from services.step_service import StepService
from services.audit_service import AuditService
from models.user import User
from utils.exceptions import ValidationException, NotFoundException, DatabaseException

router = APIRouter()


def _template_to_response(template) -> TemplateResponse:
    """Convert a WorkflowTemplate model to TemplateResponse."""
    return TemplateResponse(
        id=template.id,
        name=template.name,
        description=template.description,
        tags=json.loads(template.tags),
        step_configs=[TemplateStepConfig(**s) for s in json.loads(template.step_configs)],
        created_by=template.created_by,
        created_at=template.created_at,
        updated_at=template.updated_at,
        is_active=template.is_active,
    )


# ---------------------------------------------------------------------------
# Template CRUD
# ---------------------------------------------------------------------------

@router.get("/", response_model=List[TemplateResponse])
async def list_templates(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(require_role(["admin", "editor"])),
):
    """List all available workflow templates."""
    service = TemplateService()
    templates = service.get_all_templates(skip=skip, limit=limit)
    return [_template_to_response(t) for t in templates]


@router.post("/", response_model=TemplateResponse, status_code=status.HTTP_201_CREATED)
async def create_template(
    data: TemplateCreate,
    current_user: User = Depends(require_role(["admin", "editor"])),
):
    """Create a new workflow template (admin/editor only)."""
    try:
        service = TemplateService()
        template = service.create_template(data, current_user.id)
        AuditService().log_action(
            user_id=current_user.id,
            action="create_template",
            entity_type="workflow_template",
            entity_id=template.id,
            details=f"Created template: {template.name}",
        )
        return _template_to_response(template)
    except ValidationException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
    except DatabaseException as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.detail)


@router.get("/{template_id}", response_model=TemplateResponse)
async def get_template(
    template_id: int,
    current_user: User = Depends(require_role(["admin", "editor"])),
):
    """Get a workflow template by ID."""
    try:
        service = TemplateService()
        template = service.get_template_by_id(template_id)
        return _template_to_response(template)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)


@router.delete("/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(
    template_id: int,
    current_user: User = Depends(require_role(["admin"])),
):
    """Soft-delete a workflow template (admin only)."""
    try:
        service = TemplateService()
        service.delete_template(template_id, current_user.id)
        AuditService().log_action(
            user_id=current_user.id,
            action="delete_template",
            entity_type="workflow_template",
            entity_id=template_id,
            details=f"Deleted template ID: {template_id}",
        )
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)


# ---------------------------------------------------------------------------
# Clone: instantiate a template as a real workflow
# ---------------------------------------------------------------------------

@router.post("/{template_id}/clone", response_model=WorkflowResponse, status_code=status.HTTP_201_CREATED)
async def clone_template(
    template_id: int,
    data: TemplateClone,
    current_user: User = Depends(require_role(["admin", "editor"])),
):
    """
    Instantiate a template as a new workflow with its steps.

    The caller supplies a new workflow name (and optional description).
    Steps are created exactly as defined in the template.
    """
    try:
        template_service = TemplateService()
        template = template_service.get_template_by_id(template_id)
    except NotFoundException as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.detail)

    # Create the workflow
    workflow_service = WorkflowService()
    try:
        workflow = workflow_service.create_workflow(
            WorkflowCreate(
                name=data.name,
                description=data.description or template.description,
                status="draft",
            ),
            user_id=current_user.id,
        )
    except ValidationException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
    except DatabaseException as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.detail)

    # Create steps from template definition
    step_service = StepService()
    step_configs = json.loads(template.step_configs)
    for step_def in step_configs:
        try:
            step_service.create_step(
                workflow_id=workflow.id,
                data=StepCreate(
                    workflow_id=workflow.id,
                    name=step_def["name"],
                    step_type=step_def["step_type"],
                    config=step_def["config"],
                    order=step_def["order"],
                ),
                user_id=current_user.id,
            )
        except (ValidationException, DatabaseException) as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Failed to create step '{step_def['name']}': {e.detail}",
            )

    AuditService().log_action(
        user_id=current_user.id,
        action="clone_template",
        entity_type="workflow_template",
        entity_id=template_id,
        details=f"Cloned template '{template.name}' → workflow '{workflow.name}' (ID {workflow.id})",
    )

    return workflow
