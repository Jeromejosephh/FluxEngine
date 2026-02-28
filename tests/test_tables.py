"""Table management tests"""
import os
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
    """Create a table with name/age columns, return table_id"""
    r = client.post("/api/tables/", json={
        "name": "people",
        "description": "Test people table",
        "schema_definition": {
            "columns": [
                {"name": "name", "type": "VARCHAR"},
                {"name": "age",  "type": "INTEGER"}
            ]
        }
    }, headers=auth_headers)
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture(scope="function")
def sample_row(sample_table, auth_headers):
    """Insert a single row into sample_table, return (table_id, row_id)"""
    r = client.post(f"/api/tables/{sample_table}/data", json={
        "rows": [{"name": "Alice", "age": 30}]
    }, headers=auth_headers)
    assert r.status_code == 201, r.text

    rows_r = client.get(f"/api/tables/{sample_table}/data", headers=auth_headers)
    row_id = rows_r.json()["rows"][0]["_row_id"]
    return sample_table, row_id


# ==============================================================================
# Auth guard tests (no DB needed)
# ==============================================================================

def test_list_tables_requires_auth():
    response = client.get("/api/tables/")
    assert response.status_code == 401


def test_create_table_requires_auth():
    response = client.post("/api/tables/", json={
        "name": "Test Table",
        "description": "A test table",
        "schema_definition": {
            "columns": [
                {"name": "id", "type": "INTEGER"},
                {"name": "name", "type": "VARCHAR"}
            ]
        }
    })
    assert response.status_code == 401


def test_update_row_requires_auth():
    r = client.put("/api/tables/1/data/1", json={"data": {"name": "Bob"}})
    assert r.status_code == 401


def test_delete_row_requires_auth():
    r = client.delete("/api/tables/1/data/1")
    assert r.status_code == 401


# ==============================================================================
# PUT /api/tables/{table_id}/data/{row_id}
# ==============================================================================

class TestUpdateRow:

    def test_update_row_success(self, sample_row, auth_headers):
        table_id, row_id = sample_row
        r = client.put(f"/api/tables/{table_id}/data/{row_id}",
                       json={"data": {"age": 31}},
                       headers=auth_headers)
        assert r.status_code == 200
        assert r.json() == {"updated": 1, "row_id": row_id}

        rows = client.get(f"/api/tables/{table_id}/data", headers=auth_headers).json()["rows"]
        assert rows[0]["age"] == 31
        assert rows[0]["name"] == "Alice"  # unchanged

    def test_update_multiple_columns(self, sample_row, auth_headers):
        table_id, row_id = sample_row
        r = client.put(f"/api/tables/{table_id}/data/{row_id}",
                       json={"data": {"name": "Bob", "age": 25}},
                       headers=auth_headers)
        assert r.status_code == 200

        rows = client.get(f"/api/tables/{table_id}/data", headers=auth_headers).json()["rows"]
        assert rows[0]["name"] == "Bob"
        assert rows[0]["age"] == 25

    def test_update_row_not_found(self, sample_table, auth_headers):
        r = client.put(f"/api/tables/{sample_table}/data/9999",
                       json={"data": {"age": 99}},
                       headers=auth_headers)
        assert r.status_code == 404

    def test_update_row_unknown_column(self, sample_row, auth_headers):
        table_id, row_id = sample_row
        r = client.put(f"/api/tables/{table_id}/data/{row_id}",
                       json={"data": {"nonexistent": "value"}},
                       headers=auth_headers)
        assert r.status_code == 422

    def test_update_row_empty_data(self, sample_row, auth_headers):
        table_id, row_id = sample_row
        r = client.put(f"/api/tables/{table_id}/data/{row_id}",
                       json={"data": {}},
                       headers=auth_headers)
        assert r.status_code == 422

    def test_update_row_table_not_found(self, auth_headers, test_db):
        r = client.put("/api/tables/9999/data/1",
                       json={"data": {"age": 1}},
                       headers=auth_headers)
        assert r.status_code == 404


# ==============================================================================
# DELETE /api/tables/{table_id}/data/{row_id}
# ==============================================================================

class TestDeleteRow:

    def test_delete_row_success(self, sample_row, auth_headers):
        table_id, row_id = sample_row
        r = client.delete(f"/api/tables/{table_id}/data/{row_id}", headers=auth_headers)
        assert r.status_code == 204

        rows = client.get(f"/api/tables/{table_id}/data", headers=auth_headers).json()["rows"]
        assert len(rows) == 0

    def test_delete_row_not_found(self, sample_table, auth_headers):
        r = client.delete(f"/api/tables/{sample_table}/data/9999", headers=auth_headers)
        assert r.status_code == 404

    def test_delete_row_table_not_found(self, auth_headers, test_db):
        r = client.delete("/api/tables/9999/data/1", headers=auth_headers)
        assert r.status_code == 404

    def test_delete_row_already_deleted(self, sample_row, auth_headers):
        table_id, row_id = sample_row
        client.delete(f"/api/tables/{table_id}/data/{row_id}", headers=auth_headers)
        r = client.delete(f"/api/tables/{table_id}/data/{row_id}", headers=auth_headers)
        assert r.status_code == 404
