"""
Tests for workflow analytics and database backup/restore.
"""
import os
import io
import pytest
from fastapi.testclient import TestClient

from main import app
from services.duckdb_service import DuckDBService
from services.auth_service import AuthService
from schemas.user import UserCreate

client = TestClient(app)


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture(scope="function")
def test_db_path():
    import tempfile
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(db_path)
    yield db_path
    for path in [db_path, f"{db_path}.wal"]:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


@pytest.fixture(scope="function")
def test_db(test_db_path, monkeypatch):
    from utils import config
    monkeypatch.setattr(config.settings, "DATABASE_PATH", test_db_path)
    db = DuckDBService()
    db.init_db()
    yield db
    db.close()


@pytest.fixture(scope="function")
def admin_token(test_db):
    auth = AuthService()
    auth.create_user(UserCreate(
        email="admin@test.com",
        password="password123",
        full_name="Admin User",
        role="admin"
    ))
    return auth.authenticate_user("admin@test.com", "password123").access_token


@pytest.fixture(scope="function")
def editor_token(test_db):
    auth = AuthService()
    auth.create_user(UserCreate(
        email="editor@test.com",
        password="password123",
        full_name="Editor User",
        role="editor"
    ))
    return auth.authenticate_user("editor@test.com", "password123").access_token


@pytest.fixture(scope="function")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="function")
def editor_headers(editor_token):
    return {"Authorization": f"Bearer {editor_token}"}


@pytest.fixture(scope="function")
def workflow_with_runs(auth_headers, test_db):
    """Active workflow with a table + 3 runs executed."""
    # Create table
    r = client.post("/api/tables/", json={
        "name": "items",
        "schema_definition": {"columns": [{"name": "val", "type": "INTEGER"}]}
    }, headers=auth_headers)
    tid = r.json()["id"]
    client.post(f"/api/tables/{tid}/data", json={"rows": [{"val": 1}, {"val": 2}]}, headers=auth_headers)

    # Create workflow
    r = client.post("/api/workflows/", json={"name": "Analytics WF", "status": "draft"}, headers=auth_headers)
    wf_id = r.json()["id"]
    client.post(f"/api/workflows/{wf_id}/steps", json={
        "name": "q", "step_type": "query", "workflow_id": wf_id, "order": 0,
        "config": {"table_id": tid}
    }, headers=auth_headers)
    client.put(f"/api/workflows/{wf_id}", json={"status": "active"}, headers=auth_headers)

    # Run 3 times
    for _ in range(3):
        client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)

    return wf_id


# ==============================================================================
# Analytics
# ==============================================================================

class TestWorkflowAnalytics:

    def test_analytics_requires_auth(self, test_db):
        r = client.get("/api/workflows/1/analytics")
        assert r.status_code == 401

    def test_analytics_workflow_not_found(self, auth_headers, test_db):
        r = client.get("/api/workflows/9999/analytics", headers=auth_headers)
        assert r.status_code == 404

    def test_analytics_no_runs(self, auth_headers, test_db):
        r = client.post("/api/workflows/", json={"name": "Empty WF", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        r2 = client.get(f"/api/workflows/{wf_id}/analytics", headers=auth_headers)
        assert r2.status_code == 200
        data = r2.json()
        assert data["total_runs"] == 0
        assert data["success_rate"] == 0.0
        assert data["first_run_at"] is None
        assert data["last_run_at"] is None

    def test_analytics_counts(self, auth_headers, test_db, workflow_with_runs):
        r = client.get(f"/api/workflows/{workflow_with_runs}/analytics", headers=auth_headers)
        assert r.status_code == 200
        data = r.json()
        assert data["total_runs"] == 3
        assert data["successful_runs"] == 3
        assert data["failed_runs"] == 0
        assert data["success_rate"] == 1.0

    def test_analytics_success_rate(self, auth_headers, test_db, workflow_with_runs):
        r = client.get(f"/api/workflows/{workflow_with_runs}/analytics", headers=auth_headers)
        data = r.json()
        assert 0.0 <= data["success_rate"] <= 1.0

    def test_analytics_timestamps(self, auth_headers, test_db, workflow_with_runs):
        r = client.get(f"/api/workflows/{workflow_with_runs}/analytics", headers=auth_headers)
        data = r.json()
        assert data["first_run_at"] is not None
        assert data["last_run_at"] is not None

    def test_analytics_recent_runs(self, auth_headers, test_db, workflow_with_runs):
        r = client.get(f"/api/workflows/{workflow_with_runs}/analytics", headers=auth_headers)
        data = r.json()
        # All 3 runs just happened — should appear in both windows
        assert data["runs_last_7_days"] == 3
        assert data["runs_last_30_days"] == 3

    def test_analytics_avg_steps(self, auth_headers, test_db, workflow_with_runs):
        r = client.get(f"/api/workflows/{workflow_with_runs}/analytics", headers=auth_headers)
        data = r.json()
        assert data["avg_steps_per_run"] == 1.0   # workflow has 1 step

    def test_analytics_workflow_name(self, auth_headers, test_db, workflow_with_runs):
        r = client.get(f"/api/workflows/{workflow_with_runs}/analytics", headers=auth_headers)
        assert r.json()["workflow_name"] == "Analytics WF"


# ==============================================================================
# Backup / Restore
# ==============================================================================

class TestBackupRestore:

    def test_backup_requires_auth(self, test_db):
        r = client.get("/api/admin/backup")
        assert r.status_code == 401

    def test_backup_requires_admin(self, editor_headers, test_db):
        r = client.get("/api/admin/backup", headers=editor_headers)
        assert r.status_code == 403

    def test_backup_returns_file(self, auth_headers, test_db):
        r = client.get("/api/admin/backup", headers=auth_headers)
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/octet-stream"
        assert "fluxengine_backup.db" in r.headers.get("content-disposition", "")
        assert len(r.content) > 0

    def test_backup_content_is_valid_duckdb(self, auth_headers, test_db):
        import tempfile, duckdb
        r = client.get("/api/admin/backup", headers=auth_headers)
        assert r.status_code == 200
        fd, tmp = tempfile.mkstemp(suffix=".db")
        try:
            os.close(fd)
            with open(tmp, "wb") as f:
                f.write(r.content)
            conn = duckdb.connect(tmp, read_only=True)
            conn.execute("SELECT 1").fetchall()
            conn.close()
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

    def test_restore_requires_auth(self, test_db):
        r = client.post("/api/admin/restore", files={"file": ("backup.db", b"data", "application/octet-stream")})
        assert r.status_code == 401

    def test_restore_requires_admin(self, editor_headers, test_db):
        r = client.post("/api/admin/restore",
                        files={"file": ("backup.db", b"data", "application/octet-stream")},
                        headers=editor_headers)
        assert r.status_code == 403

    def test_restore_rejects_non_db_extension(self, auth_headers, test_db):
        r = client.post("/api/admin/restore",
                        files={"file": ("backup.txt", b"data", "application/octet-stream")},
                        headers=auth_headers)
        assert r.status_code == 422

    def test_restore_rejects_invalid_db_file(self, auth_headers, test_db):
        r = client.post("/api/admin/restore",
                        files={"file": ("backup.db", b"not a real db file", "application/octet-stream")},
                        headers=auth_headers)
        assert r.status_code == 422

    def test_restore_valid_db(self, auth_headers, test_db, test_db_path):
        import tempfile, duckdb

        # Create a minimal valid DuckDB file
        fd, src = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.unlink(src)
        try:
            conn = duckdb.connect(src)
            conn.execute("CREATE TABLE t (id INTEGER)")
            conn.close()

            with open(src, "rb") as f:
                db_bytes = f.read()

            r = client.post("/api/admin/restore",
                            files={"file": ("backup.db", db_bytes, "application/octet-stream")},
                            headers=auth_headers)
            assert r.status_code == 200
            assert "restored" in r.json()["detail"].lower()
        finally:
            for p in [src, f"{src}.wal"]:
                try:
                    os.unlink(p)
                except FileNotFoundError:
                    pass
