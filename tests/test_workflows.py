"""
Workflow execution tests

Covers:
- Workflow CRUD endpoints
- Step creation and listing
- Table data insert/query
- Workflow execution (query + transform steps)
- Auth enforcement on all workflow endpoints
"""
import os
import json
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
    """Isolated temp DB for each test"""
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
    """Patched DuckDBService pointing at the temp DB"""
    from utils import config
    monkeypatch.setattr(config.settings, "DATABASE_PATH", test_db_path)
    db = DuckDBService()
    db.init_db()
    yield db
    db.close()


@pytest.fixture(scope="function")
def admin_token(test_db):
    """Create an admin user and return a valid JWT token"""
    auth = AuthService()
    auth.create_user(UserCreate(
        email="admin@test.com",
        password="password123",
        full_name="Admin User",
        role="admin"
    ))
    token = auth.authenticate_user("admin@test.com", "password123")
    return token.access_token


@pytest.fixture(scope="function")
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="function")
def sample_table(auth_headers, test_db):
    """Create a table and insert two rows, return the table id"""
    r = client.post("/api/tables/", json={
        "name": "tickets",
        "description": "Support tickets",
        "schema_definition": {
            "columns": [
                {"name": "issue_type", "type": "VARCHAR"},
                {"name": "priority",   "type": "VARCHAR"},
                {"name": "status",     "type": "VARCHAR"}
            ]
        }
    }, headers=auth_headers)
    assert r.status_code == 201, r.text
    table_id = r.json()["id"]

    client.post(f"/api/tables/{table_id}/data", json={
        "rows": [
            {"issue_type": "login_fail",  "priority": "high",   "status": "open"},
            {"issue_type": "slow_system", "priority": "medium", "status": "open"},
            {"issue_type": "password",    "priority": "low",    "status": "closed"},
        ]
    }, headers=auth_headers)

    return table_id


# ==============================================================================
# Workflow CRUD
# ==============================================================================

class TestWorkflowCRUD:

    def test_list_workflows_requires_auth(self):
        r = client.get("/api/workflows/")
        assert r.status_code == 401

    def test_create_workflow_requires_auth(self):
        r = client.post("/api/workflows/", json={"name": "Test", "status": "draft"})
        assert r.status_code == 401

    def test_create_workflow(self, auth_headers, test_db):
        r = client.post("/api/workflows/", json={
            "name": "My Workflow",
            "description": "Test workflow",
            "status": "draft"
        }, headers=auth_headers)
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "My Workflow"
        assert data["status"] == "draft"
        assert "id" in data

    def test_get_workflow(self, auth_headers, test_db):
        r = client.post("/api/workflows/", json={"name": "WF Get", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        r2 = client.get(f"/api/workflows/{wf_id}", headers=auth_headers)
        assert r2.status_code == 200
        assert r2.json()["id"] == wf_id

    def test_get_workflow_not_found(self, auth_headers, test_db):
        r = client.get("/api/workflows/9999", headers=auth_headers)
        assert r.status_code == 404

    def test_update_workflow_status(self, auth_headers, test_db):
        r = client.post("/api/workflows/", json={"name": "WF Update", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        r2 = client.put(f"/api/workflows/{wf_id}", json={"status": "active"}, headers=auth_headers)
        assert r2.status_code == 200
        assert r2.json()["status"] == "active"

    def test_delete_workflow(self, auth_headers, test_db):
        r = client.post("/api/workflows/", json={"name": "WF Delete", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        r2 = client.delete(f"/api/workflows/{wf_id}", headers=auth_headers)
        assert r2.status_code == 204
        r3 = client.get(f"/api/workflows/{wf_id}", headers=auth_headers)
        assert r3.status_code == 404

    def test_list_workflows(self, auth_headers, test_db):
        client.post("/api/workflows/", json={"name": "WF A", "status": "draft"}, headers=auth_headers)
        client.post("/api/workflows/", json={"name": "WF B", "status": "draft"}, headers=auth_headers)
        r = client.get("/api/workflows/", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()) >= 2


# ==============================================================================
# Steps
# ==============================================================================

class TestStepCRUD:

    def test_create_query_step(self, auth_headers, test_db, sample_table):
        r = client.post("/api/workflows/", json={"name": "WF Steps", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]

        r2 = client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "Get open tickets",
            "step_type": "query",
            "workflow_id": wf_id,
            "order": 0,
            "config": {"table_id": sample_table, "filters": [{"column": "status", "op": "eq", "value": "open"}]}
        }, headers=auth_headers)
        assert r2.status_code == 201
        step = r2.json()
        assert step["step_type"] == "query"
        assert step["order"] == 0

    def test_create_transform_step(self, auth_headers, test_db, sample_table):
        r = client.post("/api/workflows/", json={"name": "WF Transform", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]

        r2 = client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "Keep key fields",
            "step_type": "transform",
            "workflow_id": wf_id,
            "order": 0,
            "config": {"select_columns": ["issue_type", "priority"]}
        }, headers=auth_headers)
        assert r2.status_code == 201

    def test_list_steps(self, auth_headers, test_db, sample_table):
        r = client.post("/api/workflows/", json={"name": "WF List Steps", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        for i in range(3):
            client.post(f"/api/workflows/{wf_id}/steps", json={
                "name": f"Step {i}",
                "step_type": "transform",
                "workflow_id": wf_id,
                "order": i,
                "config": {"select_columns": ["issue_type"]}
            }, headers=auth_headers)
        r2 = client.get(f"/api/workflows/{wf_id}/steps", headers=auth_headers)
        assert r2.status_code == 200
        steps = r2.json()
        assert len(steps) == 3
        assert [s["order"] for s in steps] == [0, 1, 2]

    def test_invalid_step_config_rejected(self, auth_headers, test_db):
        r = client.post("/api/workflows/", json={"name": "WF Bad Step", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        r2 = client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "Bad transform",
            "step_type": "transform",
            "workflow_id": wf_id,
            "order": 0,
            "config": {}   # missing select_columns and filter
        }, headers=auth_headers)
        assert r2.status_code == 422


# ==============================================================================
# Table data
# ==============================================================================

class TestTableData:

    def test_insert_and_query_rows(self, auth_headers, test_db):
        r = client.post("/api/tables/", json={
            "name": "data_test",
            "schema_definition": {"columns": [
                {"name": "name", "type": "VARCHAR"},
                {"name": "score", "type": "INTEGER"}
            ]}
        }, headers=auth_headers)
        tid = r.json()["id"]

        r2 = client.post(f"/api/tables/{tid}/data", json={
            "rows": [{"name": "Alice", "score": 90}, {"name": "Bob", "score": 75}]
        }, headers=auth_headers)
        assert r2.status_code == 201
        assert r2.json()["inserted"] == 2

        r3 = client.get(f"/api/tables/{tid}/data", headers=auth_headers)
        assert r3.status_code == 200
        data = r3.json()
        assert data["count"] == 2
        names = [row["name"] for row in data["rows"]]
        assert "Alice" in names and "Bob" in names

    def test_insert_unknown_column_rejected(self, auth_headers, test_db):
        r = client.post("/api/tables/", json={
            "name": "strict_table",
            "schema_definition": {"columns": [{"name": "name", "type": "VARCHAR"}]}
        }, headers=auth_headers)
        tid = r.json()["id"]
        r2 = client.post(f"/api/tables/{tid}/data", json={
            "rows": [{"name": "Alice", "unknown_col": "bad"}]
        }, headers=auth_headers)
        assert r2.status_code == 422


# ==============================================================================
# Workflow execution
# ==============================================================================

class TestWorkflowExecution:

    def _create_active_workflow(self, auth_headers, table_id):
        """Helper: create a workflow with a query + transform step, set active"""
        r = client.post("/api/workflows/", json={"name": "Exec Test", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]

        client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "Get open tickets",
            "step_type": "query",
            "workflow_id": wf_id,
            "order": 0,
            "config": {"table_id": table_id, "filters": [{"column": "status", "op": "eq", "value": "open"}]}
        }, headers=auth_headers)

        client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "Key fields only",
            "step_type": "transform",
            "workflow_id": wf_id,
            "order": 1,
            "config": {"select_columns": ["issue_type", "priority"]}
        }, headers=auth_headers)

        client.put(f"/api/workflows/{wf_id}", json={"status": "active"}, headers=auth_headers)
        return wf_id

    def test_run_workflow_returns_results(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        r = client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)
        assert r.status_code == 200
        result = r.json()
        assert result["success"] is True
        assert result["workflow_id"] == wf_id
        assert len(result["steps"]) == 2

    def test_run_workflow_query_step_filters_correctly(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        r = client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)
        result = r.json()
        # query step should return only the 2 open tickets (not the closed one)
        query_step = result["steps"][0]
        assert query_step["rows_out"] == 2

    def test_run_workflow_transform_step_projects_columns(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        r = client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)
        result = r.json()
        final = result["final_output"]
        assert len(final) == 2
        # Only issue_type and priority should be present — not status
        for row in final:
            assert "issue_type" in row
            assert "priority" in row
            assert "status" not in row

    def test_run_draft_workflow_rejected(self, auth_headers, test_db):
        r = client.post("/api/workflows/", json={"name": "Draft WF", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        r2 = client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)
        assert r2.status_code == 422

    def test_run_nonexistent_workflow_returns_404(self, auth_headers, test_db):
        r = client.post("/api/workflows/9999/run", headers=auth_headers)
        assert r.status_code == 404

    def test_run_requires_auth(self):
        r = client.post("/api/workflows/1/run")
        assert r.status_code == 401


# ==============================================================================
# Execution History
# ==============================================================================

class TestExecutionHistory:

    def _create_active_workflow(self, auth_headers, sample_table):
        """Helper: create a 2-step active workflow against sample_table"""
        r = client.post("/api/workflows/", json={"name": "History WF", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "All rows", "step_type": "query", "workflow_id": wf_id, "order": 0,
            "config": {"table_id": sample_table}
        }, headers=auth_headers)
        client.put(f"/api/workflows/{wf_id}", json={"status": "active"}, headers=auth_headers)
        return wf_id

    def test_run_creates_execution_record(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)

        r = client.get(f"/api/workflows/{wf_id}/runs", headers=auth_headers)
        assert r.status_code == 200
        runs = r.json()
        assert len(runs) == 1
        run = runs[0]
        assert run["workflow_id"] == wf_id
        assert run["success"] is True
        assert run["step_count"] == 1
        assert len(run["steps"]) == 1
        assert run["steps"][0]["step_type"] == "query"
        assert "id" in run
        assert "executed_at" in run

    def test_run_history_records_multiple_runs(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        for _ in range(3):
            client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)

        r = client.get(f"/api/workflows/{wf_id}/runs", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()) == 3

    def test_run_history_pagination(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        for _ in range(3):
            client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)

        r = client.get(f"/api/workflows/{wf_id}/runs?skip=0&limit=2", headers=auth_headers)
        assert len(r.json()) == 2

        r2 = client.get(f"/api/workflows/{wf_id}/runs?skip=2&limit=2", headers=auth_headers)
        assert len(r2.json()) == 1

    def test_run_history_empty(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        r = client.get(f"/api/workflows/{wf_id}/runs", headers=auth_headers)
        assert r.status_code == 200
        assert r.json() == []

    def test_run_history_newest_first(self, auth_headers, test_db, sample_table):
        wf_id = self._create_active_workflow(auth_headers, sample_table)
        for _ in range(2):
            client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)

        runs = client.get(f"/api/workflows/{wf_id}/runs", headers=auth_headers).json()
        assert runs[0]["id"] > runs[1]["id"]

    def test_run_history_requires_auth(self):
        r = client.get("/api/workflows/1/runs")
        assert r.status_code == 401

    def test_run_history_workflow_not_found(self, auth_headers, test_db):
        r = client.get("/api/workflows/9999/runs", headers=auth_headers)
        assert r.status_code == 404

    def test_failed_run_is_recorded(self, auth_headers, test_db):
        # Draft workflow — run will be rejected before execution, so use
        # a workflow with no steps pointing at a nonexistent table to force failure
        r = client.post("/api/workflows/", json={"name": "Fail WF", "status": "draft"}, headers=auth_headers)
        wf_id = r.json()["id"]
        client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "Bad query", "step_type": "query", "workflow_id": wf_id, "order": 0,
            "config": {"table_id": 99999}
        }, headers=auth_headers)
        client.put(f"/api/workflows/{wf_id}", json={"status": "active"}, headers=auth_headers)

        run_r = client.post(f"/api/workflows/{wf_id}/run", headers=auth_headers)
        # Execution may return 200 with success=false, or 500 — either records history
        if run_r.status_code == 200:
            assert run_r.json()["success"] is False
            runs = client.get(f"/api/workflows/{wf_id}/runs", headers=auth_headers).json()
            assert len(runs) == 1
            assert runs[0]["success"] is False
            assert runs[0]["error"] is not None
