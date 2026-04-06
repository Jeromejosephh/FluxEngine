"""
Tests for recently added features:
- Per-user data isolation (tables + workflows)
- Case-insensitive string filtering
- Contains filter (query step SQL + transform step Python)
- Template activation with sample rows
- Draft workflow run (no status check)
- Workflow name uniqueness per user
"""
import os
import pytest
from fastapi.testclient import TestClient

from main import app
from services.duckdb_service import DuckDBService

client = TestClient(app)


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture(scope="function")
def test_db_path():
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)
    yield path
    for p in [path, f"{path}.wal"]:
        try:
            os.unlink(p)
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


def _make_headers(email: str, role: str = "admin") -> dict:
    client.post("/api/auth/register", json={
        "email": email, "password": "pass12345", "full_name": "Test User", "role": role
    })
    r = client.post("/api/auth/login", data={"username": email, "password": "pass12345"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="function")
def user_a(test_db):
    return _make_headers("user_a@test.com", role="editor")


@pytest.fixture(scope="function")
def user_b(test_db):
    return _make_headers("user_b@test.com", role="editor")


def _create_table_with_rows(headers, name, rows):
    cols = [{"name": k, "type": "VARCHAR"} for k in rows[0].keys()]
    r = client.post("/api/tables/", json={
        "name": name,
        "schema_definition": {"columns": cols}
    }, headers=headers)
    assert r.status_code == 201, r.text
    tid = r.json()["id"]
    client.post(f"/api/tables/{tid}/data", json={"rows": rows}, headers=headers)
    return tid


def _create_workflow_with_steps(headers, wf_name, steps):
    r = client.post("/api/workflows/", json={"name": wf_name, "status": "draft"}, headers=headers)
    assert r.status_code == 201, r.text
    wf_id = r.json()["id"]
    for i, step in enumerate(steps):
        step_payload = {"name": step["name"], "step_type": step["step_type"],
                        "workflow_id": wf_id, "order": i, "config": step["config"]}
        client.post(f"/api/workflows/{wf_id}/steps", json=step_payload, headers=headers)
    return wf_id


# ==============================================================================
# Per-user data isolation
# ==============================================================================

class TestTableIsolation:
    def test_editor_cannot_see_other_users_tables(self, user_a, user_b, test_db):
        _create_table_with_rows(user_a, "user_a_secret", [{"val": "x"}])
        r = client.get("/api/tables/", headers=user_b)
        assert r.status_code == 200
        assert "user_a_secret" not in [t["name"] for t in r.json()]

    def test_editor_cannot_get_other_users_table_by_id(self, user_a, user_b, test_db):
        tid = _create_table_with_rows(user_a, "private_table", [{"val": "x"}])
        r = client.get(f"/api/tables/{tid}", headers=user_b)
        assert r.status_code == 404

    def test_two_users_can_have_same_table_name(self, user_a, user_b, test_db):
        cols = [{"name": "x", "type": "VARCHAR"}]
        r1 = client.post("/api/tables/", json={"name": "shared", "schema_definition": {"columns": cols}}, headers=user_a)
        r2 = client.post("/api/tables/", json={"name": "shared", "schema_definition": {"columns": cols}}, headers=user_b)
        assert r1.status_code == 201
        assert r2.status_code == 201

    def test_same_user_cannot_duplicate_table_name(self, user_a, test_db):
        cols = [{"name": "x", "type": "VARCHAR"}]
        client.post("/api/tables/", json={"name": "dupe_table", "schema_definition": {"columns": cols}}, headers=user_a)
        r2 = client.post("/api/tables/", json={"name": "dupe_table", "schema_definition": {"columns": cols}}, headers=user_a)
        assert r2.status_code == 422


class TestWorkflowIsolation:
    def test_editor_cannot_see_other_users_workflows(self, user_a, user_b, test_db):
        client.post("/api/workflows/", json={"name": "secret_wf", "status": "draft"}, headers=user_a)
        r = client.get("/api/workflows/", headers=user_b)
        assert r.status_code == 200
        assert "secret_wf" not in [w["name"] for w in r.json()]

    def test_editor_cannot_get_other_users_workflow_by_id(self, user_a, user_b, test_db):
        r = client.post("/api/workflows/", json={"name": "private_wf", "status": "draft"}, headers=user_a)
        wf_id = r.json()["id"]
        assert client.get(f"/api/workflows/{wf_id}", headers=user_b).status_code == 404


# ==============================================================================
# Workflow name uniqueness per user
# ==============================================================================

class TestWorkflowNameUniqueness:
    def test_same_name_different_users_allowed(self, user_a, user_b, test_db):
        r1 = client.post("/api/workflows/", json={"name": "my_wf", "status": "draft"}, headers=user_a)
        r2 = client.post("/api/workflows/", json={"name": "my_wf", "status": "draft"}, headers=user_b)
        assert r1.status_code == 201
        assert r2.status_code == 201

    def test_duplicate_name_same_user_rejected(self, user_a, test_db):
        client.post("/api/workflows/", json={"name": "dupe_wf", "status": "draft"}, headers=user_a)
        r2 = client.post("/api/workflows/", json={"name": "dupe_wf", "status": "draft"}, headers=user_a)
        assert r2.status_code == 422

    def test_case_insensitive_uniqueness(self, user_a, test_db):
        client.post("/api/workflows/", json={"name": "MyWorkflow", "status": "draft"}, headers=user_a)
        r2 = client.post("/api/workflows/", json={"name": "myworkflow", "status": "draft"}, headers=user_a)
        assert r2.status_code == 422

    def test_rename_to_existing_name_rejected(self, user_a, test_db):
        client.post("/api/workflows/", json={"name": "wf_one", "status": "draft"}, headers=user_a)
        r2 = client.post("/api/workflows/", json={"name": "wf_two", "status": "draft"}, headers=user_a)
        wf_id = r2.json()["id"]
        r3 = client.put(f"/api/workflows/{wf_id}/", json={"name": "wf_one"}, headers=user_a)
        assert r3.status_code == 422


# ==============================================================================
# Case-insensitive filtering
# ==============================================================================

class TestCaseInsensitiveFilter:
    def test_eq_filter_case_insensitive_in_query_step(self, user_a, test_db):
        tid = _create_table_with_rows(user_a, "ci_q_table", [
            {"status": "OPEN"}, {"status": "closed"}, {"status": "Open"}
        ])
        wf_id = _create_workflow_with_steps(user_a, "ci_q_wf", [
            {"name": "q", "step_type": "query", "config": {
                "table_id": tid,
                "filters": [{"column": "status", "op": "eq", "value": "open"}]
            }}
        ])
        r = client.post(f"/api/workflows/{wf_id}/run/", json={}, headers=user_a)
        assert r.status_code == 200
        assert r.json()["steps"][0]["rows_out"] == 2  # "OPEN" and "Open"

    def test_eq_filter_case_insensitive_in_transform_step(self, user_a, test_db):
        tid = _create_table_with_rows(user_a, "ci_t_table", [
            {"status": "Applied"}, {"status": "APPLIED"}, {"status": "rejected"}
        ])
        wf_id = _create_workflow_with_steps(user_a, "ci_t_wf", [
            {"name": "q", "step_type": "query", "config": {"table_id": tid}},
            {"name": "tf", "step_type": "transform", "config": {
                "filter": {"column": "status", "op": "eq", "value": "applied"}
            }}
        ])
        r = client.post(f"/api/workflows/{wf_id}/run/", json={}, headers=user_a)
        assert r.status_code == 200
        assert r.json()["steps"][1]["rows_out"] == 2


# ==============================================================================
# Contains filter
# ==============================================================================

class TestContainsFilter:
    def test_contains_in_query_step(self, user_a, test_db):
        tid = _create_table_with_rows(user_a, "contains_q_table", [
            {"note": "Meeting with Alice"},
            {"note": "Lunch break"},
            {"note": "alice followup"},
        ])
        wf_id = _create_workflow_with_steps(user_a, "contains_q_wf", [
            {"name": "q", "step_type": "query", "config": {
                "table_id": tid,
                "filters": [{"column": "note", "op": "contains", "value": "alice"}]
            }}
        ])
        r = client.post(f"/api/workflows/{wf_id}/run/", json={}, headers=user_a)
        assert r.status_code == 200
        assert r.json()["steps"][0]["rows_out"] == 2

    def test_contains_in_transform_step(self, user_a, test_db):
        tid = _create_table_with_rows(user_a, "contains_t_table", [
            {"note": "Meeting with Alice"},
            {"note": "Lunch break"},
            {"note": "alice followup"},
        ])
        wf_id = _create_workflow_with_steps(user_a, "contains_t_wf", [
            {"name": "q", "step_type": "query", "config": {"table_id": tid}},
            {"name": "tf", "step_type": "transform", "config": {
                "filter": {"column": "note", "op": "contains", "value": "alice"}
            }}
        ])
        r = client.post(f"/api/workflows/{wf_id}/run/", json={}, headers=user_a)
        assert r.status_code == 200
        assert r.json()["steps"][1]["rows_out"] == 2

    def test_contains_no_match(self, user_a, test_db):
        tid = _create_table_with_rows(user_a, "contains_none_table", [
            {"note": "nothing relevant"}, {"note": "other stuff"}
        ])
        wf_id = _create_workflow_with_steps(user_a, "contains_none_wf", [
            {"name": "q", "step_type": "query", "config": {
                "table_id": tid,
                "filters": [{"column": "note", "op": "contains", "value": "alice"}]
            }}
        ])
        r = client.post(f"/api/workflows/{wf_id}/run/", json={}, headers=user_a)
        assert r.status_code == 200
        assert r.json()["steps"][0]["rows_out"] == 0


# ==============================================================================
# Draft workflow run
# ==============================================================================

class TestDraftWorkflowRun:
    def test_draft_workflow_runs_successfully(self, user_a, test_db):
        tid = _create_table_with_rows(user_a, "draft_run_table", [{"val": "hello"}])
        wf_id = _create_workflow_with_steps(user_a, "draft_run_wf", [
            {"name": "q", "step_type": "query", "config": {"table_id": tid}}
        ])
        r = client.post(f"/api/workflows/{wf_id}/run/", json={}, headers=user_a)
        assert r.status_code == 200
        assert r.json()["success"] is True
        assert r.json()["steps"][0]["rows_out"] == 1

    def test_active_workflow_still_runs(self, user_a, test_db):
        tid = _create_table_with_rows(user_a, "active_run_table", [{"val": "x"}])
        r = client.post("/api/workflows/", json={"name": "active_run_wf", "status": "active"}, headers=user_a)
        wf_id = r.json()["id"]
        client.post(f"/api/workflows/{wf_id}/steps", json={
            "name": "q", "step_type": "query", "workflow_id": wf_id, "order": 0,
            "config": {"table_id": tid}
        }, headers=user_a)
        r2 = client.post(f"/api/workflows/{wf_id}/run/", json={}, headers=user_a)
        assert r2.status_code == 200
        assert r2.json()["success"] is True


# ==============================================================================
# Template activation with sample rows
# ==============================================================================

class TestTemplateActivationSampleRows:
    def test_job_tracker_has_sample_rows(self, user_a, test_db):
        r = client.post("/api/templates/catalog/job_tracker/activate",
                        json={"inputs": {"email": "test@example.com"}},
                        headers=user_a)
        assert r.status_code == 201
        table_id = r.json()["tables"][0]["id"]
        r2 = client.get(f"/api/tables/{table_id}/data", headers=user_a)
        assert r2.status_code == 200
        assert r2.json()["count"] >= 3

    def test_expense_tracker_has_sample_rows(self, user_a, test_db):
        r = client.post("/api/templates/catalog/expense_tracker/activate",
                        json={"inputs": {"email": "test@example.com"}},
                        headers=user_a)
        assert r.status_code == 201
        table_id = r.json()["tables"][0]["id"]
        r2 = client.get(f"/api/tables/{table_id}/data", headers=user_a)
        assert r2.json()["count"] >= 3

    def test_contact_followup_has_sample_rows(self, user_a, test_db):
        r = client.post("/api/templates/catalog/contact_followup/activate",
                        json={"inputs": {"email": "test@example.com"}},
                        headers=user_a)
        assert r.status_code == 201
        table_id = r.json()["tables"][0]["id"]
        r2 = client.get(f"/api/tables/{table_id}/data", headers=user_a)
        assert r2.json()["count"] >= 3
