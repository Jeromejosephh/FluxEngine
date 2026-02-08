"""
Comprehensive Authentication Tests

Test coverage for:
- AuthService methods (password hashing, JWT tokens, user CRUD)
- Authentication endpoints (/register, /login, /me)
- Role-based access control (RBAC)
- Security edge cases and error handling
"""
import pytest
import jwt as pyjwt
from datetime import timedelta, datetime
from fastapi.testclient import TestClient
from fastapi import FastAPI, Depends, HTTPException, status
from typing import Dict
import tempfile
import os

from main import app
from services.duckdb_service import DuckDBService
from services.auth_service import AuthService
from services.audit_service import AuditService
from schemas.user import UserCreate
from schemas.auth import Token
from utils.exceptions import AuthenticationException
from utils.security import require_admin, require_editor
from routes.auth import oauth2_scheme


# ==============================================================================
# FIXTURES - Database and Service Setup
# ==============================================================================

@pytest.fixture(scope="function")
def test_db_path():
    """Create temporary database file path"""
    # Generate temp path but don't create file - let DuckDB create it
    import tempfile
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)  # Close file descriptor
    os.unlink(db_path)  # Delete the empty file so DuckDB can create a new database

    yield db_path

    # Cleanup
    try:
        os.unlink(db_path)
    except FileNotFoundError:
        pass
    try:
        os.unlink(f"{db_path}.wal")
    except FileNotFoundError:
        pass


@pytest.fixture(scope="function")
def test_db_service(test_db_path, monkeypatch):
    """Provide isolated DuckDBService for each test"""
    # Override settings to use test database
    from utils.config import settings
    monkeypatch.setattr(settings, "DATABASE_PATH", test_db_path)

    db_service = DuckDBService()
    db_service.init_db()

    yield db_service

    db_service.close()


@pytest.fixture(scope="function")
def auth_service(test_db_service):
    """Provide AuthService with test database"""
    service = AuthService()
    # Override the db_service to use test database
    service.db_service = test_db_service
    return service


@pytest.fixture(scope="function")
def audit_service(test_db_service):
    """Provide AuditService with test database"""
    service = AuditService()
    service.db_service = test_db_service
    return service


# ==============================================================================
# FIXTURES - Test Data
# ==============================================================================

@pytest.fixture
def sample_user_data():
    """Sample editor user creation data"""
    return UserCreate(
        email="editor@test.com",
        password="password123",
        full_name="Test Editor",
        role="editor"
    )


@pytest.fixture
def admin_user_data():
    """Sample admin user creation data"""
    return UserCreate(
        email="admin@test.com",
        password="adminpass123",
        full_name="Test Admin",
        role="admin"
    )


@pytest.fixture
def created_user(auth_service, sample_user_data):
    """Pre-created editor user in database"""
    user = auth_service.create_user(sample_user_data)
    return user


@pytest.fixture
def admin_user(auth_service, admin_user_data):
    """Pre-created admin user in database"""
    user = auth_service.create_user(admin_user_data)
    return user


@pytest.fixture
def inactive_user(auth_service, test_db_service):
    """User with is_active=False"""
    user_data = UserCreate(
        email="inactive@test.com",
        password="password123",
        full_name="Inactive User",
        role="editor"
    )
    user = auth_service.create_user(user_data)

    # Set user to inactive directly in database
    test_db_service.execute(
        "UPDATE users SET is_active = FALSE WHERE id = ?",
        (user.id,)
    )

    return user


# ==============================================================================
# FIXTURES - FastAPI Test Client with Dependency Overrides
# ==============================================================================

@pytest.fixture(scope="function")
def client(test_db_service, monkeypatch):
    """FastAPI TestClient with test database dependency override"""
    from utils.config import settings
    monkeypatch.setattr(settings, "DATABASE_PATH", test_db_service.db_path)

    # Create new test client
    test_client = TestClient(app)

    return test_client


@pytest.fixture
def auth_headers(client, created_user, sample_user_data) -> Dict[str, str]:
    """Valid JWT authentication headers for editor user"""
    response = client.post(
        "/api/auth/login",
        data={
            "username": sample_user_data.email,
            "password": sample_user_data.password
        }
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(client, admin_user, admin_user_data) -> Dict[str, str]:
    """Valid JWT authentication headers for admin user"""
    response = client.post(
        "/api/auth/login",
        data={
            "username": admin_user_data.email,
            "password": admin_user_data.password
        }
    )
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ==============================================================================
# UNIT TESTS - Password Hashing
# ==============================================================================

class TestPasswordHashing:
    """Test password hashing and verification"""

    def test_hash_password_returns_bcrypt_hash(self, auth_service):
        """Verify password is hashed with bcrypt format"""
        plain_password = "testpassword123"
        hashed = auth_service.hash_password(plain_password)

        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")
        assert hashed != plain_password
        assert len(hashed) > 50

    def test_verify_password_with_correct_password(self, auth_service):
        """Verify correct password validation"""
        plain_password = "testpassword123"
        hashed = auth_service.hash_password(plain_password)

        is_valid = auth_service.verify_password(plain_password, hashed)
        assert is_valid is True

    def test_verify_password_with_wrong_password(self, auth_service):
        """Verify incorrect password rejection"""
        plain_password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = auth_service.hash_password(plain_password)

        is_valid = auth_service.verify_password(wrong_password, hashed)
        assert is_valid is False

    def test_hash_password_different_hashes_for_same_password(self, auth_service):
        """Verify salting - same password yields different hashes"""
        plain_password = "testpassword123"
        hash1 = auth_service.hash_password(plain_password)
        hash2 = auth_service.hash_password(plain_password)

        # Hashes should be different due to random salt
        assert hash1 != hash2

        # But both should verify correctly
        assert auth_service.verify_password(plain_password, hash1)
        assert auth_service.verify_password(plain_password, hash2)


# ==============================================================================
# UNIT TESTS - JWT Token Operations
# ==============================================================================

class TestJWTTokens:
    """Test JWT token creation and validation"""

    def test_create_access_token_with_user_data(self, auth_service):
        """Create token with user claims"""
        token = auth_service.create_access_token(
            data={"sub": 1, "email": "test@test.com", "role": "admin"}
        )

        assert isinstance(token, str)
        # JWT has 3 parts: header.payload.signature
        assert len(token.split(".")) == 3

    def test_decode_token_extracts_user_data(self, auth_service):
        """Decode token and extract claims"""
        token = auth_service.create_access_token(
            data={"sub": 1, "email": "test@test.com", "role": "admin"}
        )

        token_data = auth_service.decode_token(token)

        assert token_data.user_id == 1
        assert token_data.email == "test@test.com"
        assert token_data.role == "admin"

    def test_create_token_with_custom_expiration(self, auth_service):
        """Token with custom expiration delta"""
        token = auth_service.create_access_token(
            data={"sub": 1, "email": "test@test.com", "role": "admin"},
            expires_delta=timedelta(minutes=5)
        )

        # Decode without validation to inspect claims
        from utils.config import settings
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        exp_timestamp = payload["exp"]
        exp_datetime = datetime.fromtimestamp(exp_timestamp)
        now = datetime.utcnow()

        # Should expire in approximately 5 minutes
        delta = exp_datetime - now
        assert 4.5 <= delta.total_seconds() / 60 <= 5.5

    def test_decode_expired_token_raises_exception(self, auth_service):
        """Expired token raises AuthenticationException"""
        token = auth_service.create_access_token(
            data={"sub": 1, "email": "test@test.com", "role": "admin"},
            expires_delta=timedelta(seconds=-1)
        )

        with pytest.raises(AuthenticationException) as exc_info:
            auth_service.decode_token(token)

        assert "expired" in str(exc_info.value.detail).lower()

    def test_decode_invalid_token_raises_exception(self, auth_service):
        """Invalid token raises AuthenticationException"""
        invalid_token = "invalid.token.string"

        with pytest.raises(AuthenticationException) as exc_info:
            auth_service.decode_token(invalid_token)

        assert "invalid" in str(exc_info.value.detail).lower()

    def test_decode_token_with_wrong_secret_raises_exception(self, auth_service):
        """Token signed with different secret fails validation"""
        # Create token with different secret
        wrong_secret_token = pyjwt.encode(
            {"sub": 1, "email": "test@test.com", "role": "admin"},
            "wrong-secret-key",
            algorithm="HS256"
        )

        with pytest.raises(AuthenticationException) as exc_info:
            auth_service.decode_token(wrong_secret_token)

        assert "invalid" in str(exc_info.value.detail).lower()


# ==============================================================================
# UNIT TESTS - User CRUD Operations
# ==============================================================================

class TestUserCRUD:
    """Test user creation and retrieval"""

    def test_create_user_stores_in_database(self, auth_service, sample_user_data):
        """User creation stores all fields correctly"""
        user = auth_service.create_user(sample_user_data)

        assert user.id is not None  # Auto-generated
        assert user.email == sample_user_data.email
        assert user.hashed_password != sample_user_data.password
        assert user.hashed_password.startswith("$2b$")
        assert user.full_name == sample_user_data.full_name
        assert user.role == sample_user_data.role
        assert user.is_active is True
        assert user.created_at is not None
        assert user.updated_at is not None

    def test_create_duplicate_user_raises_error(self, auth_service, sample_user_data):
        """Duplicate email raises ValueError"""
        auth_service.create_user(sample_user_data)

        with pytest.raises(ValueError) as exc_info:
            auth_service.create_user(sample_user_data)

        assert "already exists" in str(exc_info.value).lower()

    def test_get_user_by_email_returns_user(self, auth_service, created_user):
        """Retrieve user by email"""
        user = auth_service.get_user_by_email(created_user.email)

        assert user is not None
        assert user.id == created_user.id
        assert user.email == created_user.email
        assert user.full_name == created_user.full_name

    def test_get_user_by_email_not_found_returns_none(self, auth_service):
        """Non-existent email returns None"""
        user = auth_service.get_user_by_email("nonexistent@test.com")
        assert user is None

    def test_get_user_by_id_returns_user(self, auth_service, created_user):
        """Retrieve user by ID"""
        user = auth_service.get_user_by_id(created_user.id)

        assert user is not None
        assert user.id == created_user.id
        assert user.email == created_user.email

    def test_get_user_by_id_not_found_returns_none(self, auth_service):
        """Non-existent ID returns None"""
        user = auth_service.get_user_by_id(9999)
        assert user is None


# ==============================================================================
# UNIT TESTS - User Authentication
# ==============================================================================

class TestUserAuthentication:
    """Test user authentication and token generation"""

    def test_authenticate_user_with_valid_credentials(self, auth_service, created_user, sample_user_data):
        """Valid credentials return Token"""
        token = auth_service.authenticate_user(
            sample_user_data.email,
            sample_user_data.password
        )

        assert isinstance(token, Token)
        assert token.access_token is not None
        assert isinstance(token.access_token, str)
        assert token.token_type == "bearer"

    def test_authenticate_user_with_invalid_email(self, auth_service):
        """Invalid email raises AuthenticationException"""
        with pytest.raises(AuthenticationException) as exc_info:
            auth_service.authenticate_user("nonexistent@test.com", "password123")

        assert "invalid" in str(exc_info.value.detail).lower()

    def test_authenticate_user_with_wrong_password(self, auth_service, created_user, sample_user_data):
        """Wrong password raises AuthenticationException"""
        with pytest.raises(AuthenticationException) as exc_info:
            auth_service.authenticate_user(sample_user_data.email, "wrongpassword")

        assert "invalid" in str(exc_info.value.detail).lower()

    def test_authenticate_inactive_user_raises_exception(self, auth_service, inactive_user):
        """Inactive user cannot authenticate"""
        with pytest.raises(AuthenticationException) as exc_info:
            auth_service.authenticate_user("inactive@test.com", "password123")

        assert "inactive" in str(exc_info.value.detail).lower()

    def test_get_current_user_from_valid_token(self, auth_service, created_user, sample_user_data):
        """Extract user from valid JWT token"""
        token = auth_service.authenticate_user(
            sample_user_data.email,
            sample_user_data.password
        )

        user = auth_service.get_current_user(token.access_token)

        assert user.id == created_user.id
        assert user.email == created_user.email

    def test_get_current_user_with_invalid_token_raises_exception(self, auth_service):
        """Invalid token raises AuthenticationException"""
        with pytest.raises(AuthenticationException):
            auth_service.get_current_user("invalid.token.string")

    def test_get_current_user_with_nonexistent_user_id(self, auth_service):
        """Token with non-existent user_id raises exception"""
        # Create token manually with non-existent user_id
        token = auth_service.create_access_token(
            data={"sub": 9999, "email": "fake@test.com", "role": "admin"}
        )

        with pytest.raises(AuthenticationException) as exc_info:
            auth_service.get_current_user(token)

        assert "not found" in str(exc_info.value.detail).lower()


# ==============================================================================
# INTEGRATION TESTS - Registration Endpoint
# ==============================================================================

class TestRegistrationEndpoint:
    """Test POST /api/auth/register endpoint"""

    def test_register_new_user_success(self, client):
        """POST /api/auth/register creates new user"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "newuser@test.com",
                "password": "password123",
                "full_name": "New User",
                "role": "editor"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert data["id"] is not None
        assert data["email"] == "newuser@test.com"
        assert data["full_name"] == "New User"
        assert data["role"] == "editor"
        assert data["is_active"] is True
        assert "password" not in data
        assert "hashed_password" not in data
        assert data["created_at"] is not None

    def test_register_duplicate_email_returns_400(self, client, created_user):
        """Duplicate email returns 400 Bad Request"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": created_user.email,
                "password": "password123",
                "full_name": "Duplicate User",
                "role": "editor"
            }
        )

        assert response.status_code == 400
        assert "already exists" in response.json()["detail"].lower()

    def test_register_invalid_email_format_returns_422(self, client):
        """Invalid email format fails validation"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "not-an-email",
                "password": "password123",
                "full_name": "Test User",
                "role": "editor"
            }
        )

        assert response.status_code == 422

    def test_register_short_password_returns_422(self, client):
        """Password < 8 chars fails validation"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "test@test.com",
                "password": "short",
                "full_name": "Test User",
                "role": "editor"
            }
        )

        assert response.status_code == 422

    def test_register_invalid_role_returns_422(self, client):
        """Role not in ['admin', 'editor'] fails validation"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "test@test.com",
                "password": "password123",
                "full_name": "Test User",
                "role": "superuser"
            }
        )

        assert response.status_code == 422

    def test_register_missing_required_fields_returns_422(self, client):
        """Missing required fields fails validation"""
        # Missing email
        response = client.post(
            "/api/auth/register",
            json={
                "password": "password123",
                "full_name": "Test User",
                "role": "editor"
            }
        )
        assert response.status_code == 422

        # Missing password
        response = client.post(
            "/api/auth/register",
            json={
                "email": "test@test.com",
                "full_name": "Test User",
                "role": "editor"
            }
        )
        assert response.status_code == 422


# ==============================================================================
# INTEGRATION TESTS - Login Endpoint
# ==============================================================================

class TestLoginEndpoint:
    """Test POST /api/auth/login endpoint"""

    def test_login_with_valid_credentials(self, client, created_user, sample_user_data):
        """POST /api/auth/login returns JWT token"""
        response = client.post(
            "/api/auth/login",
            data={
                "username": sample_user_data.email,
                "password": sample_user_data.password
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
        assert isinstance(data["access_token"], str)
        assert len(data["access_token"]) > 20

    def test_login_with_invalid_email(self, client):
        """Invalid email returns 401"""
        response = client.post(
            "/api/auth/login",
            data={
                "username": "nonexistent@test.com",
                "password": "password123"
            }
        )

        assert response.status_code == 401

    def test_login_with_wrong_password(self, client, created_user, sample_user_data):
        """Wrong password returns 401"""
        response = client.post(
            "/api/auth/login",
            data={
                "username": sample_user_data.email,
                "password": "wrongpassword"
            }
        )

        assert response.status_code == 401

    def test_login_inactive_user_returns_401(self, client, inactive_user):
        """Inactive user cannot login"""
        response = client.post(
            "/api/auth/login",
            data={
                "username": "inactive@test.com",
                "password": "password123"
            }
        )

        assert response.status_code == 401

    def test_login_returns_token_with_correct_claims(self, client, created_user, sample_user_data):
        """Token contains correct user claims"""
        response = client.post(
            "/api/auth/login",
            data={
                "username": sample_user_data.email,
                "password": sample_user_data.password
            }
        )

        token = response.json()["access_token"]

        # Decode token without verification for testing
        from utils.config import settings
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert payload["sub"] == created_user.id
        assert payload["email"] == created_user.email
        assert payload["role"] == created_user.role

    def test_login_with_form_data_format(self, client, created_user, sample_user_data):
        """Login accepts OAuth2PasswordRequestForm format"""
        response = client.post(
            "/api/auth/login",
            data={
                "username": sample_user_data.email,
                "password": sample_user_data.password
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        assert response.status_code == 200
        assert "access_token" in response.json()


# ==============================================================================
# INTEGRATION TESTS - Get Current User Endpoint
# ==============================================================================

class TestGetCurrentUserEndpoint:
    """Test GET /api/auth/me endpoint"""

    def test_get_current_user_with_valid_token(self, client, auth_headers, created_user):
        """GET /api/auth/me returns current user"""
        response = client.get("/api/auth/me", headers=auth_headers)

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == created_user.id
        assert data["email"] == created_user.email
        assert data["full_name"] == created_user.full_name
        assert data["role"] == created_user.role
        assert "password" not in data
        assert "hashed_password" not in data

    def test_get_current_user_without_token_returns_401(self, client):
        """Missing token returns 401"""
        response = client.get("/api/auth/me")
        assert response.status_code == 401

    def test_get_current_user_with_invalid_token_returns_401(self, client):
        """Invalid token returns 401"""
        response = client.get(
            "/api/auth/me",
            headers={"Authorization": "Bearer invalid.token.string"}
        )
        assert response.status_code == 401

    def test_get_current_user_with_expired_token_returns_401(self, client, auth_service, created_user):
        """Expired token returns 401"""
        # Create expired token
        expired_token = auth_service.create_access_token(
            data={"sub": created_user.id, "email": created_user.email, "role": created_user.role},
            expires_delta=timedelta(seconds=-1)
        )

        response = client.get(
            "/api/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )

        assert response.status_code == 401


# ==============================================================================
# SECURITY TESTS - Role-Based Access Control
# ==============================================================================

class TestRoleBasedAccessControl:
    """Test RBAC decorators and permissions"""

    @pytest.fixture
    def test_app(self):
        """Create test app with protected endpoints"""
        test_app = FastAPI()

        @test_app.get("/admin-only")
        async def admin_only_endpoint(user=Depends(require_admin)):
            return {"message": "Admin access granted", "user": user.email}

        @test_app.get("/editor-allowed")
        async def editor_allowed_endpoint(user=Depends(require_editor)):
            return {"message": "Editor access granted", "user": user.email}

        return test_app

    @pytest.fixture
    def test_client_rbac(self, test_app, test_db_service, monkeypatch):
        """Test client with RBAC endpoints"""
        from utils.config import settings
        monkeypatch.setattr(settings, "DATABASE_PATH", test_db_service.db_path)
        return TestClient(test_app)

    def test_admin_can_access_admin_endpoint(self, test_client_rbac, admin_headers):
        """Admin role can access admin-only endpoint"""
        response = test_client_rbac.get("/admin-only", headers=admin_headers)
        assert response.status_code == 200

    def test_editor_cannot_access_admin_endpoint(self, test_client_rbac, auth_headers):
        """Editor role denied from admin endpoint"""
        response = test_client_rbac.get("/admin-only", headers=auth_headers)
        assert response.status_code == 403

    def test_editor_can_access_editor_endpoint(self, test_client_rbac, auth_headers):
        """Editor role can access editor endpoint"""
        response = test_client_rbac.get("/editor-allowed", headers=auth_headers)
        assert response.status_code == 200

    def test_admin_can_access_editor_endpoint(self, test_client_rbac, admin_headers):
        """Admin can access editor endpoints"""
        response = test_client_rbac.get("/editor-allowed", headers=admin_headers)
        assert response.status_code == 200

    def test_unauthenticated_cannot_access_protected_endpoint(self, test_client_rbac):
        """No token returns 401 on protected endpoint"""
        response = test_client_rbac.get("/admin-only")
        assert response.status_code == 401


# ==============================================================================
# EDGE CASES & ERROR HANDLING
# ==============================================================================

class TestInputValidation:
    """Test input validation edge cases"""

    def test_register_with_unicode_in_full_name(self, client):
        """Unicode characters in full_name"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "unicode@test.com",
                "password": "password123",
                "full_name": "José García 李明",
                "role": "editor"
            }
        )

        assert response.status_code == 201
        assert response.json()["full_name"] == "José García 李明"

    def test_register_with_special_chars_in_password(self, client):
        """Special characters in password"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "special@test.com",
                "password": "P@ssw0rd!#$%",
                "full_name": "Test User",
                "role": "editor"
            }
        )

        assert response.status_code == 201

        # Verify can login with that password
        login_response = client.post(
            "/api/auth/login",
            data={
                "username": "special@test.com",
                "password": "P@ssw0rd!#$%"
            }
        )
        assert login_response.status_code == 200

    def test_login_email_case_sensitivity(self, client, created_user, sample_user_data):
        """Test email matching case sensitivity"""
        # Try login with uppercase email
        response = client.post(
            "/api/auth/login",
            data={
                "username": sample_user_data.email.upper(),
                "password": sample_user_data.password
            }
        )

        # Should fail since email is case-sensitive in current implementation
        assert response.status_code == 401


class TestSecurityEdgeCases:
    """Test security-related edge cases"""

    def test_token_contains_no_sensitive_data(self, auth_service, created_user):
        """JWT token should not contain password"""
        token = auth_service.create_access_token(
            data={"sub": created_user.id, "email": created_user.email, "role": created_user.role}
        )

        # Decode without verification
        from utils.config import settings
        payload = pyjwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])

        assert "password" not in payload
        assert "hashed_password" not in payload

    def test_registration_response_excludes_password(self, client):
        """Registration response should not include password"""
        response = client.post(
            "/api/auth/register",
            json={
                "email": "security@test.com",
                "password": "password123",
                "full_name": "Security Test",
                "role": "editor"
            }
        )

        data = response.json()
        assert "password" not in data
        assert "hashed_password" not in data

    def test_get_current_user_response_excludes_password(self, client, auth_headers):
        """Current user response should not include password"""
        response = client.get("/api/auth/me", headers=auth_headers)

        data = response.json()
        assert "password" not in data
        assert "hashed_password" not in data


# ==============================================================================
# HEALTH CHECK TEST (Keep existing)
# ==============================================================================

def test_health_check():
    """Test health check endpoint"""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "FluxEngine"}
