"""Custom exceptions"""


class FluxEngineException(Exception):
    """Base exception for FluxEngine"""
    
    def __init__(self, detail: str, status_code: int = 500, error_code: str = "INTERNAL_ERROR"):
        self.detail = detail
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(self.detail)


class AuthenticationException(FluxEngineException):
    """Exception raised for authentication errors"""
    
    def __init__(self, detail: str = "Authentication failed"):
        super().__init__(
            detail=detail,
            status_code=401,
            error_code="AUTHENTICATION_FAILED"
        )


class AuthorizationException(FluxEngineException):
    """Exception raised for authorization errors"""
    
    def __init__(self, detail: str = "Access denied"):
        super().__init__(
            detail=detail,
            status_code=403,
            error_code="ACCESS_DENIED"
        )


class NotFoundException(FluxEngineException):
    """Exception raised when resource is not found"""
    
    def __init__(self, detail: str = "Resource not found"):
        super().__init__(
            detail=detail,
            status_code=404,
            error_code="NOT_FOUND"
        )


class ValidationException(FluxEngineException):
    """Exception raised for validation errors"""
    
    def __init__(self, detail: str = "Validation failed"):
        super().__init__(
            detail=detail,
            status_code=422,
            error_code="VALIDATION_FAILED"
        )


class DatabaseException(FluxEngineException):
    """Exception raised for database errors"""
    
    def __init__(self, detail: str = "Database operation failed"):
        super().__init__(
            detail=detail,
            status_code=500,
            error_code="DATABASE_ERROR"
        )
