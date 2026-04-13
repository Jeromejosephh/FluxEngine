"""
FluxEngine - Workflow Engine Backend
Main application entry point
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from routes import auth, tables, workflows, admin, templates, forms
from routes.inbound_webhooks import management_router as webhooks_mgmt_router, public_router as webhooks_public_router
from services.duckdb_service import DuckDBService
from services.scheduler_service import start_scheduler, stop_scheduler
from utils.exceptions import FluxEngineException
from utils.config import settings
from utils.limiter import limiter


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup: Initialize database
    db_service = DuckDBService()
    db_service.init_db()
    print("✓ Database initialized")

    start_scheduler()
    print("✓ Scheduler started")

    yield

    # Shutdown: Cleanup
    stop_scheduler()
    print("✓ Application shutdown")


# Initialize FastAPI app
app = FastAPI(
    title="FluxEngine",
    description="Workflow Engine API",
    version="1.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Global exception handlers
@app.exception_handler(FluxEngineException)
async def flux_engine_exception_handler(request: Request, exc: FluxEngineException):
    """Handle custom application exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "error_code": exc.error_code}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    # TODO: Add proper logging here
    print(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "error_code": "INTERNAL_ERROR"}
    )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "FluxEngine"}




# Register routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(tables.router, prefix="/api/tables", tags=["Tables"])
app.include_router(workflows.router, prefix="/api/workflows", tags=["Workflows"])
app.include_router(admin.router, prefix="/api/admin", tags=["Admin"])
app.include_router(templates.router, prefix="/api/templates", tags=["Templates"])
app.include_router(webhooks_mgmt_router, prefix="/api/webhooks", tags=["Webhooks"])
app.include_router(webhooks_public_router, prefix="/webhooks", tags=["Webhooks (Public)"])
app.include_router(forms.router, prefix="/forms", tags=["Forms (Public)"])


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
