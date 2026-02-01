"""
FluxEngine - Workflow Engine Backend
Main application entry point
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from routes import auth, tables, workflows
from services.duckdb_service import DuckDBService
from utils.exceptions import FluxEngineException
from utils.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup: Initialize database
    db_service = DuckDBService()
    db_service.init_db()
    print("✓ Database initialized")
    
    yield
    
    # Shutdown: Cleanup
    print("✓ Application shutdown")


# Initialize FastAPI app
app = FastAPI(
    title="FluxEngine",
    description="Workflow Engine API",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
