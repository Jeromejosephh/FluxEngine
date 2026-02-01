"""Table management tests"""
import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_list_tables_requires_auth():
    """Test that listing tables requires authentication"""
    response = client.get("/api/tables/")
    assert response.status_code == 401


def test_create_table_requires_auth():
    """Test that creating tables requires authentication"""
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


# TODO: Add more comprehensive tests
# - Test table creation with valid auth
# - Test table retrieval
# - Test table update
# - Test table deletion
# - Test schema validation
# - Test access control
