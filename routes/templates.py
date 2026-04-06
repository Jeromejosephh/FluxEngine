"""Workflow template routes"""
import json
from fastapi import APIRouter, Depends, HTTPException, status
from typing import Any, Dict, List

from schemas.template import TemplateCreate, TemplateResponse, TemplateStepConfig, TemplateClone, CatalogActivate
from schemas.workflow import WorkflowCreate, WorkflowResponse
from schemas.step import StepCreate, StepResponse
from routes.auth import oauth2_scheme
from utils.security import require_role
from services.auth_service import AuthService
from services.template_service import TemplateService
from services.workflow_service import WorkflowService
from services.step_service import StepService
from services.audit_service import AuditService
from services.table_service import TableService
from services.duckdb_service import DuckDBService
from schemas.table import TableCreate
from models.user import User
from utils.exceptions import ValidationException, NotFoundException, DatabaseException
from catalog import CATALOG, CATALOG_BY_ID

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
# Catalog: pre-built templates — must be registered BEFORE /{template_id}
# ---------------------------------------------------------------------------

@router.get("/catalog", response_model=List[Dict[str, Any]])
async def list_catalog(
    current_user: User = Depends(require_role(["admin", "editor"])),
):
    """Return the hardcoded product template catalog."""
    return CATALOG


@router.post("/catalog/{template_id}/activate", status_code=status.HTTP_201_CREATED)
async def activate_catalog_template(
    template_id: str,
    data: CatalogActivate,
    current_user: User = Depends(require_role(["admin", "editor"])),
):
    """
    Activate a catalog template for the current user.
    Creates tables, workflow, steps, inbound webhooks, and a daily 9am schedule.
    Returns workflow info plus form tokens for each table.
    """
    import secrets
    tmpl = CATALOG_BY_ID.get(template_id)
    if not tmpl:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Catalog template '{template_id}' not found")

    for inp in tmpl.get("inputs", []):
        key = inp["key"]
        if key not in data.inputs or not data.inputs[key].strip():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required input: '{inp['label']}'",
            )

    table_service = TableService()
    db = DuckDBService()

    # Create tables, physical tables, and inbound webhooks
    table_map: Dict[str, int] = {}
    tables_out = []
    for tbl_def in tmpl.get("tables", []):
        try:
            table = table_service.create_table(
                TableCreate(
                    name=tbl_def["name"],
                    description=tbl_def.get("description"),
                    schema_definition={"columns": tbl_def["columns"]},
                ),
                user_id=current_user.id,
            )
            db.ensure_physical_table(table)
            table_map[tbl_def["key"]] = table.id

            form_token = secrets.token_urlsafe(32)
            db.create_inbound_webhook(table.id, form_token, "Form submissions", None, current_user.id)
            tables_out.append({"id": table.id, "name": table.name, "form_token": form_token})
        except ValidationException as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    # Create workflow
    wf_def = tmpl["workflow"]
    try:
        workflow = db.create_workflow(
            name=wf_def["name"],
            description=wf_def.get("description"),
            status="active",
            created_by=current_user.id,
        )
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    # Create steps with placeholders substituted
    def _substitute(obj: Any) -> Any:
        if isinstance(obj, str) and obj.startswith("{") and obj.endswith("}"):
            key = obj[1:-1]
            if key in table_map:
                return table_map[key]
            if key in data.inputs:
                return data.inputs[key]
        elif isinstance(obj, dict):
            return {k: _substitute(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_substitute(item) for item in obj]
        return obj

    step_service = StepService()
    for step_def in wf_def.get("steps", []):
        resolved_config = _substitute(step_def["config"])
        try:
            step_service.create_step(
                workflow_id=workflow.id,
                data=StepCreate(
                    workflow_id=workflow.id,
                    name=step_def["name"],
                    step_type=step_def["step_type"],
                    config=resolved_config,
                    order=step_def["order"],
                ),
                user_id=current_user.id,
            )
        except ValidationException as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.detail)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    # Auto-schedule: daily at 9am
    try:
        from services.scheduler_service import add_or_replace_job, _compute_next_run
        cron_expr = "0 9 * * *"
        db.create_schedule(
            workflow_id=workflow.id,
            cron_expr=cron_expr,
            is_enabled=True,
            created_by=current_user.id,
            next_run_at=_compute_next_run(cron_expr),
        )
        add_or_replace_job(workflow.id, cron_expr, current_user.id)
    except Exception:
        pass  # schedule failure shouldn't block activation

    AuditService().log_action(
        user_id=current_user.id,
        action="activate_catalog_template",
        entity_type="workflow",
        entity_id=workflow.id,
        details=f"Activated catalog template '{template_id}' → workflow '{workflow.name}' (ID {workflow.id})",
    )

    return {
        "workflow_id": workflow.id,
        "workflow_name": workflow.name,
        "tables": tables_out,
    }


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
