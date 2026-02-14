"""Authentication routes"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from schemas.user import UserCreate, UserResponse, UserLogin
from schemas.auth import Token
from services.auth_service import AuthService
from services.audit_service import AuditService
from utils.exceptions import AuthenticationException

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate):
    """
    Register a new user
    
    TODO: 
    - Add email verification
    - Add rate limiting
    - Add admin-only registration for admin role
    """
    auth_service = AuthService()
    audit_service = AuditService()
    
    try:
        # Create user
        user = auth_service.create_user(user_data)
        
        # Log audit entry
        audit_service.log_action(
            user_id=user.id,
            action="register",
            entity_type="user",
            entity_id=user.id,
            details=f"User registered: {user.email}"
        )
        
        return user
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login user and return JWT token
    
    TODO:
    - Add brute force protection
    - Add session management
    - Add refresh token support
    """
    auth_service = AuthService()
    audit_service = AuditService()
    
    try:
        # Authenticate user
        token = auth_service.authenticate_user(form_data.username, form_data.password)
        
        # Get user for audit log
        user = auth_service.get_user_by_email(form_data.username)
        
        # Log audit entry
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
