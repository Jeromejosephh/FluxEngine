"""Authentication routes"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from schemas.user import UserCreate, UserResponse, UserLogin
from schemas.auth import Token
from services.auth_service import AuthService
from services.audit_service import AuditService
from services.duckdb_service import DuckDBService
from utils.exceptions import AuthenticationException
from utils.limiter import limiter

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(request: Request, user_data: UserCreate):
    """Register a new user"""
    auth_service = AuthService()
    audit_service = AuditService()

    user_data.role = "editor"
    try:
        user = auth_service.create_user(user_data)
        audit_service.log_action(
            user_id=user.id,
            action="register",
            entity_type="user",
            entity_id=user.id,
            details=f"User registered: {user.email}"
        )
        return user

    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Registration failed"
        )


@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """Login user and return JWT token"""
    auth_service = AuthService()
    audit_service = AuditService()

    try:
        token = auth_service.authenticate_user(form_data.username, form_data.password)
        user = auth_service.get_user_by_email(form_data.username)
        audit_service.log_action(
            user_id=user.id if user else None,
            action="login",
            entity_type="user",
            entity_id=user.id if user else None,
            details=f"User logged in: {form_data.username}"
        )
        return token

    except AuthenticationException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.delete("/reset", status_code=status.HTTP_204_NO_CONTENT)
async def reset_account(token: str = Depends(oauth2_scheme)):
    """Delete all workflows and tables belonging to the current user."""
    auth_service = AuthService()
    try:
        user = auth_service.get_current_user(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    db = DuckDBService()

    # Collect table IDs before deleting so we can drop their data_ tables
    table_rows = db.execute(
        "SELECT id FROM tables WHERE created_by = ?", (user.id,)
    )

    # Delete dependent rows first (FK order)
    db.execute(
        "DELETE FROM steps WHERE workflow_id IN (SELECT id FROM workflows WHERE created_by = ?)",
        (user.id,),
    )
    db.execute(
        "DELETE FROM executions WHERE workflow_id IN (SELECT id FROM workflows WHERE created_by = ?)",
        (user.id,),
    )
    db.execute(
        "DELETE FROM schedules WHERE workflow_id IN (SELECT id FROM workflows WHERE created_by = ?)",
        (user.id,),
    )
    db.execute("DELETE FROM inbound_webhooks WHERE created_by = ?", (user.id,))
    db.execute("DELETE FROM workflows WHERE created_by = ?", (user.id,))

    # Drop the actual data tables and remove their metadata rows
    for row in table_rows:
        try:
            db.execute(f"DROP TABLE IF EXISTS data_{row['id']}")
        except Exception:
            pass
    db.execute("DELETE FROM tables WHERE created_by = ?", (user.id,))

    return None


@router.get("/me", response_model=UserResponse)
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    Get current authenticated user
    """
    auth_service = AuthService()
    
    try:
        user = auth_service.get_current_user(token)
        return user
    
    except AuthenticationException as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail,
            headers={"WWW-Authenticate": "Bearer"},
        )
