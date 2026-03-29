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


# ==============================================================================
# GET /api/tables/  and  GET /api/tables/{table_id}
# ==============================================================================

class TestListAndGetTable:

    def test_list_tables_empty(self, test_db, auth_headers):
        r = client.get("/api/tables/", headers=auth_headers)
        assert r.status_code == 200
        assert r.json() == []

    def test_list_tables_returns_created_table(self, sample_table, auth_headers):
        r = client.get("/api/tables/", headers=auth_headers)
        assert r.status_code == 200
        ids = [t["id"] for t in r.json()]
        assert sample_table in ids

    def test_list_tables_pagination(self, test_db, auth_headers):
        for i in range(3):
            client.post("/api/tables/", json={
                "name": f"table_{i}",
                "schema_definition": {"columns": [{"name": "x", "type": "INTEGER"}]}
            }, headers=auth_headers)
        r = client.get("/api/tables/?skip=0&limit=2", headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_get_table_by_id(self, sample_table, auth_headers):
        r = client.get(f"/api/tables/{sample_table}", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == sample_table
        assert body["name"] == "people"
        assert "columns" in body["schema_definition"]

    def test_get_table_not_found(self, test_db, auth_headers):
        r = client.get("/api/tables/9999", headers=auth_headers)
        assert r.status_code == 404

    def test_get_table_requires_auth(self, test_db):
        r = client.get("/api/tables/1")
        assert r.status_code == 401


# ==============================================================================
# POST /api/tables/
# ==============================================================================

VALID_TABLE = {
    "name": "orders",
    "description": "Customer orders",
    "schema_definition": {
        "columns": [
            {"name": "order_id", "type": "INTEGER"},
            {"name": "customer", "type": "VARCHAR"},
            {"name": "amount", "type": "FLOAT"},
        ]
    }
}


class TestCreateTable:

    def test_create_table_success(self, test_db, auth_headers):
        r = client.post("/api/tables/", json=VALID_TABLE, headers=auth_headers)
        assert r.status_code == 201
        body = r.json()
        assert body["name"] == "orders"
        assert body["description"] == "Customer orders"
        assert len(body["schema_definition"]["columns"]) == 3
        assert body["is_active"] is True

    def test_create_table_without_description(self, test_db, auth_headers):
        payload = {k: v for k, v in VALID_TABLE.items() if k != "description"}
        r = client.post("/api/tables/", json=payload, headers=auth_headers)
        assert r.status_code == 201
        assert r.json()["description"] is None

    def test_create_table_duplicate_name_rejected(self, test_db, auth_headers):
        client.post("/api/tables/", json=VALID_TABLE, headers=auth_headers)
        r = client.post("/api/tables/", json=VALID_TABLE, headers=auth_headers)
        assert r.status_code == 422

    def test_create_table_reserved_name_rejected(self, test_db, auth_headers):
        payload = {**VALID_TABLE, "name": "users"}
        r = client.post("/api/tables/", json=payload, headers=auth_headers)
        assert r.status_code == 422

    def test_create_table_invalid_name_rejected(self, test_db, auth_headers):
        payload = {**VALID_TABLE, "name": "123invalid"}
        r = client.post("/api/tables/", json=payload, headers=auth_headers)
        assert r.status_code == 422

    def test_create_table_unsupported_column_type_rejected(self, test_db, auth_headers):
        payload = {
            **VALID_TABLE,
            "schema_definition": {"columns": [{"name": "col", "type": "JSONB"}]}
        }
        r = client.post("/api/tables/", json=payload, headers=auth_headers)
        assert r.status_code == 422

    def test_create_table_duplicate_column_names_rejected(self, test_db, auth_headers):
        payload = {
            **VALID_TABLE,
            "schema_definition": {
                "columns": [
                    {"name": "col", "type": "INTEGER"},
                    {"name": "col", "type": "VARCHAR"},
                ]
            }
        }
        r = client.post("/api/tables/", json=payload, headers=auth_headers)
        assert r.status_code == 422

    def test_create_table_missing_columns_key_rejected(self, test_db, auth_headers):
        payload = {**VALID_TABLE, "schema_definition": {}}
        r = client.post("/api/tables/", json=payload, headers=auth_headers)
        assert r.status_code == 422

    def test_create_table_empty_columns_rejected(self, test_db, auth_headers):
        payload = {**VALID_TABLE, "schema_definition": {"columns": []}}
        r = client.post("/api/tables/", json=payload, headers=auth_headers)
        assert r.status_code == 422

    def test_create_table_editor_role_allowed(self, test_db, auth_headers, test_db_path, monkeypatch):
        from utils import config
        monkeypatch.setattr(config.settings, "DATABASE_PATH", test_db_path)
        auth = AuthService()
        auth.create_user(UserCreate(
            email="editor@test.com",
            password="password123",
            full_name="Editor",
            role="editor"
        ))
        token = auth.authenticate_user("editor@test.com", "password123").access_token
        r = client.post("/api/tables/", json=VALID_TABLE,
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 201


# ==============================================================================
# PUT /api/tables/{table_id}
# ==============================================================================

class TestUpdateTable:

    def test_update_table_name(self, sample_table, auth_headers):
        r = client.put(f"/api/tables/{sample_table}",
                       json={"name": "people_v2"},
                       headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["name"] == "people_v2"

    def test_update_table_description(self, sample_table, auth_headers):
        r = client.put(f"/api/tables/{sample_table}",
                       json={"description": "Updated desc"},
                       headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["description"] == "Updated desc"

    def test_update_table_schema(self, sample_table, auth_headers):
        new_schema = {"columns": [{"name": "id", "type": "INTEGER"}, {"name": "label", "type": "VARCHAR"}]}
        r = client.put(f"/api/tables/{sample_table}",
                       json={"schema_definition": new_schema},
                       headers=auth_headers)
        assert r.status_code == 200
        assert len(r.json()["schema_definition"]["columns"]) == 2

    def test_update_table_not_found(self, test_db, auth_headers):
        r = client.put("/api/tables/9999", json={"name": "ghost"}, headers=auth_headers)
        assert r.status_code == 404

    def test_update_table_duplicate_name_rejected(self, test_db, auth_headers):
        client.post("/api/tables/", json={**VALID_TABLE, "name": "first"}, headers=auth_headers)
        r2 = client.post("/api/tables/", json={**VALID_TABLE, "name": "second"}, headers=auth_headers)
        t2_id = r2.json()["id"]
        r = client.put(f"/api/tables/{t2_id}", json={"name": "first"}, headers=auth_headers)
        assert r.status_code == 422

    def test_update_table_invalid_schema_rejected(self, sample_table, auth_headers):
        r = client.put(f"/api/tables/{sample_table}",
                       json={"schema_definition": {"columns": [{"name": "col", "type": "JSONB"}]}},
                       headers=auth_headers)
        assert r.status_code == 422

    def test_update_table_requires_auth(self, test_db):
        r = client.put("/api/tables/1", json={"name": "x"})
        assert r.status_code == 401


# ==============================================================================
# DELETE /api/tables/{table_id}
# ==============================================================================

class TestDeleteTable:

    def test_delete_table_success(self, sample_table, auth_headers):
        r = client.delete(f"/api/tables/{sample_table}", headers=auth_headers)
        assert r.status_code == 204

    def test_deleted_table_not_in_list(self, sample_table, auth_headers):
        client.delete(f"/api/tables/{sample_table}", headers=auth_headers)
        r = client.get("/api/tables/", headers=auth_headers)
        ids = [t["id"] for t in r.json()]
        assert sample_table not in ids

    def test_deleted_table_get_returns_404(self, sample_table, auth_headers):
        client.delete(f"/api/tables/{sample_table}", headers=auth_headers)
        r = client.get(f"/api/tables/{sample_table}", headers=auth_headers)
        assert r.status_code == 404

    def test_delete_table_not_found(self, test_db, auth_headers):
        r = client.delete("/api/tables/9999", headers=auth_headers)
        assert r.status_code == 404

    def test_delete_table_requires_admin(self, test_db, auth_headers, test_db_path, monkeypatch):
        from utils import config
        monkeypatch.setattr(config.settings, "DATABASE_PATH", test_db_path)
        auth = AuthService()
        auth.create_user(UserCreate(
            email="editor2@test.com",
            password="password123",
            full_name="Editor",
            role="editor"
        ))
        token = auth.authenticate_user("editor2@test.com", "password123").access_token
        r = client.delete(f"/api/tables/1", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_delete_table_requires_auth(self, test_db):
        r = client.delete("/api/tables/1")
        assert r.status_code == 401


# ==============================================================================
# POST /api/tables/{table_id}/data  and  GET /api/tables/{table_id}/data
# ==============================================================================

class TestTableData:

    def test_insert_rows_success(self, sample_table, auth_headers):
        r = client.post(f"/api/tables/{sample_table}/data",
                        json={"rows": [{"name": "Bob", "age": 25}, {"name": "Carol", "age": 40}]},
                        headers=auth_headers)
        assert r.status_code == 201
        assert r.json()["inserted"] == 2

    def test_query_rows(self, sample_table, auth_headers):
        client.post(f"/api/tables/{sample_table}/data",
                    json={"rows": [{"name": "Dave", "age": 35}]},
                    headers=auth_headers)
        r = client.get(f"/api/tables/{sample_table}/data", headers=auth_headers)
        assert r.status_code == 200
        body = r.json()
        assert body["count"] == 1
        assert body["rows"][0]["name"] == "Dave"

    def test_query_rows_empty(self, sample_table, auth_headers):
        r = client.get(f"/api/tables/{sample_table}/data", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["count"] == 0
        assert r.json()["rows"] == []

    def test_insert_unknown_column_rejected(self, sample_table, auth_headers):
        r = client.post(f"/api/tables/{sample_table}/data",
                        json={"rows": [{"name": "Eve", "unknown_col": "x"}]},
                        headers=auth_headers)
        assert r.status_code == 422

    def test_insert_into_nonexistent_table(self, test_db, auth_headers):
        r = client.post("/api/tables/9999/data",
                        json={"rows": [{"name": "Ghost"}]},
                        headers=auth_headers)
        assert r.status_code == 404

    def test_query_nonexistent_table(self, test_db, auth_headers):
        r = client.get("/api/tables/9999/data", headers=auth_headers)
        assert r.status_code == 404

    def test_insert_requires_auth(self, test_db):
        r = client.post("/api/tables/1/data", json={"rows": []})
        assert r.status_code == 401

    def test_query_requires_auth(self, test_db):
        r = client.get("/api/tables/1/data")
        assert r.status_code == 401
