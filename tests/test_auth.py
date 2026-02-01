"""Authentication tests"""
import pytest
from fastapi.testclient import TestClient

from main import app

client = TestClient(app)


def test_health_check():
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "FluxEngine"}


def test_register_endpoint_exists():
    """Test that register endpoint exists"""
    response = client.post("/api/auth/register", json={
        "email": "test@example.com",
        "password": "testpassword123",
        "full_name": "Test User",
        "role": "editor"
    })
    # Should return 501 or 400 since not implemented yet
    assert response.status_code in [400, 501, 500]


def test_login_endpoint_exists():
    """Test that login endpoint exists"""
    response = client.post("/api/auth/login", data={
        "username": "test@example.com",
        "password": "testpassword123"
    })
    # Should return 401 since user doesn't exist
    assert response.status_code in [401, 500]


# TODO: Add more comprehensive tests
# - Test password hashing
# - Test JWT token generation
# - Test token validation
# - Test role-based access control
# - Test user registration flow
# - Test login flow
