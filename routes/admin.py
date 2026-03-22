"""Admin routes — backup and restore"""
import os
import shutil
import tempfile
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.responses import FileResponse

from routes.auth import oauth2_scheme
from services.auth_service import AuthService
from services.duckdb_service import DuckDBService
from services.audit_service import AuditService
from utils.config import settings
from utils.security import require_role

router = APIRouter()


async def get_current_user_from_token(token: str):
    auth_service = AuthService()
    try:
        return auth_service.get_current_user(token)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.get("/backup", response_class=FileResponse)
async def backup(
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin"]))
):
    """
    Download the current database as a .db file.
    Checkpoints the WAL first to ensure the file is consistent.
    Admin only.
    """
    user = await get_current_user_from_token(token)
    db = DuckDBService()

    # Flush WAL so the file on disk is complete
    db.execute("CHECKPOINT")

    db_path = settings.DATABASE_PATH
    if not os.path.exists(db_path):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Database file not found")

    AuditService().log_action(
        user_id=user.id,
        action="backup",
        entity_type="database",
        entity_id=0,
        details="Database backup downloaded"
    )

    return FileResponse(
        path=db_path,
        media_type="application/octet-stream",
        filename="fluxengine_backup.db",
    )


@router.post("/restore", status_code=status.HTTP_200_OK)
async def restore(
    file: UploadFile = File(...),
    token: str = Depends(oauth2_scheme),
    _: None = Depends(require_role(["admin"]))
):
    """
    Replace the current database with an uploaded .db file.
    The uploaded file must be a valid DuckDB database.
    Admin only. The application must be restarted after restore.
    """
    user = await get_current_user_from_token(token)

    if not file.filename or not file.filename.endswith(".db"):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded file must have a .db extension"
        )

    # Write upload to a temp file and validate it is a real DuckDB database
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".db")
    try:
        os.close(tmp_fd)
        content = await file.read()
        with open(tmp_path, "wb") as f:
            f.write(content)

        # Validate: try to open and run a trivial query
        import duckdb
        try:
            test_conn = duckdb.connect(tmp_path, read_only=True)
            test_conn.execute("SELECT 1").fetchall()
            test_conn.close()
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Uploaded file is not a valid DuckDB database"
            )

        db_path = settings.DATABASE_PATH
        # Close existing connection before replacing the file
        existing_db = DuckDBService()
        existing_db.close()

        shutil.copy2(tmp_path, db_path)
    finally:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

    AuditService().log_action(
        user_id=user.id,
        action="restore",
        entity_type="database",
        entity_id=0,
        details=f"Database restored from uploaded file '{file.filename}'"
    )

    return {"detail": "Database restored successfully. Restart the application to apply changes."}
