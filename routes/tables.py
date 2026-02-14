"""Table management routes"""
import json
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from schemas.table import TableCreate, TableUpdate, TableResponse
from routes.auth import oauth2_scheme
from utils.security import require_role
from services.auth_service import AuthService
from services.table_service import TableService
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


@router.get("/", response_model=List[TableResponse])
async def list_tables(
    skip: int = 0,
    limit: int = 100,
    token: str = Depends(oauth2_scheme)
):
    """List all tables with pagination"""
    # Get current user (validates token)
    user = await get_current_user_from_token(token)

    # Initialize service
    table_service = TableService()

    try:
        # Get all tables
        tables = table_service.get_all_tables(skip=skip, limit=limit)

        # Convert schema_definition from JSON string to dict for each table
        response_tables = []
        for table in tables:
            table_dict = {
                "id": table.id,
                "name": table.name,
                "description": table.description,
                "schema_definition": json.loads(table.schema_definition),
                "created_by": table.created_by,
                "created_at": table.created_at,
                "updated_at": table.updated_at,
                "is_active": table.is_active
            }
            response_tables.append(TableResponse(**table_dict))

        return response_tables

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve tables: {str(e)}"
        )


@router.get("/{table_id}", response_model=TableResponse)
async def get_table(
    table_id: int,
    token: str = Depends(oauth2_scheme)
):
    """Get table by ID"""
    # Get current user (validates token)
    user = await get_current_user_from_token(token)

    # Initialize service
    table_service = TableService()

    try:
        # Get table
        table = table_service.get_table_by_id(table_id)

        # Convert schema_definition from JSON string to dict
        return TableResponse(
            id=table.id,
            name=table.name,
            description=table.description,
            schema_definition=json.loads(table.schema_definition),
            created_by=table.created_by,
            created_at=table.created_at,
            updated_at=table.updated_at,
            is_active=table.is_active
        )

    except NotFoundException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.post("/", response_model=TableResponse, status_code=status.HTTP_201_CREATED)
async def create_table(
    table_data: TableCreate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """Create a new table (requires admin or editor role)"""
    # Get current user
    user = await get_current_user_from_token(token)

    # Initialize services
    table_service = TableService()
    audit_service = AuditService()

    try:
        # Create table
        table = table_service.create_table(table_data, user_id=user.id)

        # Log audit entry (non-blocking)
        audit_service.log_action(
            user_id=user.id,
            action="create",
            entity_type="table",
            entity_id=table.id,
            details=f"Created table: {table.name}"
        )

        # Return response with schema as dict
        return TableResponse(
            id=table.id,
            name=table.name,
            description=table.description,
            schema_definition=json.loads(table.schema_definition),
            created_by=table.created_by,
            created_at=table.created_at,
            updated_at=table.updated_at,
            is_active=table.is_active
        )

    except ValidationException as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=e.detail
        )
    except DatabaseException as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=e.detail
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.put("/{table_id}", response_model=TableResponse)
async def update_table(
    table_id: int,
    table_data: TableUpdate,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin", "editor"]))
):
    """Update table metadata (requires admin or editor role)"""
    # Get current user
    user = await get_current_user_from_token(token)

    # Initialize services
    table_service = TableService()
    audit_service = AuditService()

    try:
        # Update table
        table = table_service.update_table(table_id, table_data, user_id=user.id)

        # Log audit entry (non-blocking)
        audit_service.log_action(
            user_id=user.id,
            action="update",
            entity_type="table",
            entity_id=table.id,
            details=f"Updated table: {table.name}"
        )

        # Return response
        return TableResponse(
            id=table.id,
            name=table.name,
            description=table.description,
            schema_definition=json.loads(table.schema_definition),
            created_by=table.created_by,
            created_at=table.created_at,
            updated_at=table.updated_at,
            is_active=table.is_active
        )

    except NotFoundException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail
        )
    except ValidationException as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=e.detail
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/{table_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_table(
    table_id: int,
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin"]))
):
    """Soft delete table (requires admin role)"""
    # Get current user
    user = await get_current_user_from_token(token)

    # Initialize services
    table_service = TableService()
    audit_service = AuditService()

    try:
        # Get table name for audit before deletion
        table = table_service.get_table_by_id(table_id)
        table_name = table.name

        # Delete table
        table_service.delete_table(table_id, user_id=user.id)

        # Log audit entry (non-blocking)
        audit_service.log_action(
            user_id=user.id,
            action="delete",
            entity_type="table",
            entity_id=table_id,
            details=f"Deleted table: {table_name}"
        )

        return None  # 204 No Content

    except NotFoundException as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=e.detail
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )
