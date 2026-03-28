"""
Workflow template tests

Covers:
- Template CRUD endpoints
- Step config validation inside templates
- Auth / RBAC enforcement
- Clone template → creates workflow + steps
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
        role="admin",
    ))
    token = auth.authenticate_user("admin@test.com", "password123")
    return token.access_token


@pytest.fixture(scope="function")
def editor_token(test_db):
    auth = AuthService()
    auth.create_user(UserCreate(
        email="editor@test.com",
        password="password123",
        full_name="Editor User",
        role="editor",
    ))
    token = auth.authenticate_user("editor@test.com", "password123")
    return token.access_token


@pytest.fixture(scope="function")
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture(scope="function")
def editor_headers(editor_token):
    return {"Authorization": f"Bearer {editor_token}"}


TRANSFORM_TEMPLATE = {
    "name": "Simple Transform",
    "description": "Filters and projects rows",
    "tags": ["etl", "transform"],
    "step_configs": [
        {
            "name": "Filter active rows",
            "step_type": "transform",
            "config": {"filter": {"column": "status", "op": "eq", "value": "active"}},
            "order": 0,
        },
        {
            "name": "Select columns",
            "step_type": "transform",
            "config": {"select_columns": ["id", "name"]},
            "order": 1,
        },
    ],
}

ACTION_TEMPLATE = {
    "name": "Webhook Notifier",
    "description": "Posts data to a webhook",
    "tags": ["action", "webhook"],
    "step_configs": [
        {
            "name": "Send to webhook",
            "step_type": "action",
            "config": {"webhook_url": "https://example.com/hook", "timeout_seconds": 10},
            "order": 0,
        }
    ],
}


# ==============================================================================
# Auth guard tests
# ==============================================================================

class TestTemplateAuthGuards:
    def test_list_templates_requires_auth(self, test_db):
        r = client.get("/api/templates/")
        assert r.status_code == 401

    def test_create_template_requires_auth(self, test_db):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE)
        assert r.status_code == 401

    def test_get_template_requires_auth(self, test_db):
        r = client.get("/api/templates/1")
        assert r.status_code == 401

    def test_delete_template_requires_auth(self, test_db):
        r = client.delete("/api/templates/1")
        assert r.status_code == 401

    def test_clone_template_requires_auth(self, test_db):
        r = client.post("/api/templates/1/clone", json={"name": "My Workflow"})
        assert r.status_code == 401

    def test_create_template_editor_allowed(self, test_db, editor_headers):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=editor_headers)
        assert r.status_code == 201

    def test_delete_template_editor_forbidden(self, test_db, admin_headers, editor_headers):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]
        r = client.delete(f"/api/templates/{template_id}", headers=editor_headers)
        assert r.status_code == 403


# ==============================================================================
# Template CRUD
# ==============================================================================

class TestTemplateCRUD:
    def test_create_template(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        assert r.status_code == 201
        body = r.json()
        assert body["name"] == "Simple Transform"
        assert body["tags"] == ["etl", "transform"]
        assert len(body["step_configs"]) == 2
        assert body["is_active"] is True

    def test_list_templates_empty(self, test_db, admin_headers):
        r = client.get("/api/templates/", headers=admin_headers)
        assert r.status_code == 200
        assert r.json() == []

    def test_list_templates(self, test_db, admin_headers):
        client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        client.post("/api/templates/", json=ACTION_TEMPLATE, headers=admin_headers)
        r = client.get("/api/templates/", headers=admin_headers)
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_get_template_by_id(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]
        r = client.get(f"/api/templates/{template_id}", headers=admin_headers)
        assert r.status_code == 200
        assert r.json()["id"] == template_id

    def test_get_template_not_found(self, test_db, admin_headers):
        r = client.get("/api/templates/9999", headers=admin_headers)
        assert r.status_code == 404

    def test_delete_template(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]
        r = client.delete(f"/api/templates/{template_id}", headers=admin_headers)
        assert r.status_code == 204
        # Should be gone
        r = client.get(f"/api/templates/{template_id}", headers=admin_headers)
        assert r.status_code == 404

    def test_delete_template_not_found(self, test_db, admin_headers):
        r = client.delete("/api/templates/9999", headers=admin_headers)
        assert r.status_code == 404

    def test_deleted_template_excluded_from_list(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]
        client.delete(f"/api/templates/{template_id}", headers=admin_headers)
        r = client.get("/api/templates/", headers=admin_headers)
        assert all(t["id"] != template_id for t in r.json())

    def test_duplicate_template_name_rejected(self, test_db, admin_headers):
        client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        assert r.status_code == 422

    def test_template_tags_stored_correctly(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=ACTION_TEMPLATE, headers=admin_headers)
        assert r.json()["tags"] == ["action", "webhook"]

    def test_template_no_tags_defaults_to_empty_list(self, test_db, admin_headers):
        payload = {**TRANSFORM_TEMPLATE, "name": "No Tags", "tags": []}
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 201
        assert r.json()["tags"] == []


# ==============================================================================
# Validation
# ==============================================================================

class TestTemplateValidation:
    def test_empty_step_configs_rejected(self, test_db, admin_headers):
        payload = {**TRANSFORM_TEMPLATE, "step_configs": []}
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 422

    def test_invalid_step_type_rejected(self, test_db, admin_headers):
        payload = {
            **TRANSFORM_TEMPLATE,
            "step_configs": [
                {"name": "Bad step", "step_type": "unknown", "config": {}, "order": 0}
            ],
        }
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 422

    def test_action_step_missing_webhook_url_rejected(self, test_db, admin_headers):
        payload = {
            "name": "Bad Action Template",
            "step_configs": [
                {"name": "Missing URL", "step_type": "action", "config": {}, "order": 0}
            ],
        }
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 422

    def test_action_step_invalid_webhook_url_rejected(self, test_db, admin_headers):
        payload = {
            "name": "Bad URL Template",
            "step_configs": [
                {
                    "name": "Bad URL",
                    "step_type": "action",
                    "config": {"webhook_url": "ftp://bad.url"},
                    "order": 0,
                }
            ],
        }
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 422

    def test_transform_step_requires_filter_or_select(self, test_db, admin_headers):
        payload = {
            "name": "Empty Transform Template",
            "step_configs": [
                {"name": "Empty", "step_type": "transform", "config": {}, "order": 0}
            ],
        }
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 422

    def test_empty_name_rejected(self, test_db, admin_headers):
        payload = {**TRANSFORM_TEMPLATE, "name": ""}
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 422

    def test_negative_step_order_rejected(self, test_db, admin_headers):
        payload = {
            **TRANSFORM_TEMPLATE,
            "step_configs": [
                {
                    "name": "Bad order",
                    "step_type": "transform",
                    "config": {"select_columns": ["id"]},
                    "order": -1,
                }
            ],
        }
        r = client.post("/api/templates/", json=payload, headers=admin_headers)
        assert r.status_code == 422


# ==============================================================================
# Clone
# ==============================================================================

class TestTemplateClone:
    def test_clone_creates_workflow(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=ACTION_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]

        r = client.post(
            f"/api/templates/{template_id}/clone",
            json={"name": "My Webhook Workflow"},
            headers=admin_headers,
        )
        assert r.status_code == 201
        body = r.json()
        assert body["name"] == "My Webhook Workflow"
        assert body["status"] == "draft"

    def test_clone_inherits_template_description(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=ACTION_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]

        r = client.post(
            f"/api/templates/{template_id}/clone",
            json={"name": "Inherited Desc Workflow"},
            headers=admin_headers,
        )
        assert r.status_code == 201
        assert r.json()["description"] == ACTION_TEMPLATE["description"]

    def test_clone_uses_provided_description(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=ACTION_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]

        r = client.post(
            f"/api/templates/{template_id}/clone",
            json={"name": "Custom Desc Workflow", "description": "My custom desc"},
            headers=admin_headers,
        )
        assert r.status_code == 201
        assert r.json()["description"] == "My custom desc"

    def test_clone_creates_steps(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=TRANSFORM_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]

        clone_r = client.post(
            f"/api/templates/{template_id}/clone",
            json={"name": "Cloned Transform Workflow"},
            headers=admin_headers,
        )
        assert clone_r.status_code == 201
        workflow_id = clone_r.json()["id"]

        steps_r = client.get(f"/api/workflows/{workflow_id}/steps", headers=admin_headers)
        assert steps_r.status_code == 200
        steps = steps_r.json()
        assert len(steps) == 2
        assert steps[0]["name"] == "Filter active rows"
        assert steps[1]["name"] == "Select columns"

    def test_clone_nonexistent_template_returns_404(self, test_db, admin_headers):
        r = client.post(
            "/api/templates/9999/clone",
            json={"name": "Ghost Workflow"},
            headers=admin_headers,
        )
        assert r.status_code == 404

    def test_clone_same_template_twice_creates_two_workflows(self, test_db, admin_headers):
        r = client.post("/api/templates/", json=ACTION_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]

        r1 = client.post(
            f"/api/templates/{template_id}/clone",
            json={"name": "Clone One"},
            headers=admin_headers,
        )
        r2 = client.post(
            f"/api/templates/{template_id}/clone",
            json={"name": "Clone Two"},
            headers=admin_headers,
        )
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["id"] != r2.json()["id"]

    def test_clone_editor_allowed(self, test_db, admin_headers, editor_headers):
        r = client.post("/api/templates/", json=ACTION_TEMPLATE, headers=admin_headers)
        template_id = r.json()["id"]

        r = client.post(
            f"/api/templates/{template_id}/clone",
            json={"name": "Editor Clone"},
            headers=editor_headers,
        )
        assert r.status_code == 201
