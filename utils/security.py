"""Security utilities"""
from typing import List, Callable
from fastapi import Depends, HTTPException, status

from routes.auth import oauth2_scheme
from services.auth_service import AuthService
from utils.exceptions import AuthenticationException, AuthorizationException


def require_role(allowed_roles: List[str]) -> Callable:
    """
    Dependency factory for role-based access control
    
    Args:
        allowed_roles: List of roles allowed to access the endpoint
        
    Returns:
        Dependency function for FastAPI
        
    Example:
        @router.get("/admin-only", dependencies=[Depends(require_role(["admin"]))])
        async def admin_endpoint():
            return {"message": "Admin access granted"}
    """
    
    async def check_role(token: str = Depends(oauth2_scheme)):
        """Check if user has required role"""
        auth_service = AuthService()
        
        try:
            # Get current user from token
            user = auth_service.get_current_user(token)
            
            # Check if user has required role
            if user.role not in allowed_roles:
                raise AuthorizationException(
                    f"Access denied. Required roles: {', '.join(allowed_roles)}"
                )
            
            return user
        
        except AuthenticationException as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=e.detail,
                headers={"WWW-Authenticate": "Bearer"},
            )
        except AuthorizationException as e:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=e.detail
            )
    
    return check_role


def require_admin(token: str = Depends(oauth2_scheme)):
    """
    Dependency for admin-only endpoints
    
    Shortcut for require_role(["admin"])
    """
    return require_role(["admin"])(token)


def require_editor(token: str = Depends(oauth2_scheme)):
    """
    Dependency for editor or admin endpoints
    
    Shortcut for require_role(["admin", "editor"])
    """
    return require_role(["admin", "editor"])(token)
