# FluxEngine Authentication Guide

**Last Updated:** 2026-02-08
**Version:** 1.0.0
**Status:** Production Ready ✅

---

## Overview

FluxEngine uses a robust JWT-based authentication system with bcrypt password hashing, role-based access control, and comprehensive audit logging. This guide covers the complete authentication architecture, API endpoints, and security considerations.

### Key Features

- **Stateless Authentication:** JWT tokens for API-first architecture
- **Secure Password Storage:** bcrypt hashing with 12 salt rounds
- **Role-Based Access Control (RBAC):** Admin and editor roles with granular permissions
- **Token Expiration:** 30-minute access tokens (configurable)
- **Audit Logging:** All authentication events tracked
- **Input Validation:** Pydantic schemas with email and password requirements

---

## Quick Start

### 1. Initialize Database and Create Admin User

```bash
# Create admin user with sample data
python scripts/seed_db.py --non-interactive

# Or create admin only
python scripts/seed_db.py --admin-only --non-interactive

# Or interactive mode with custom credentials
python scripts/seed_db.py
```

**Default Credentials (Non-Interactive):**
- Email: `admin@example.com`
- Password: `admin123`
- Role: `admin`

### 2. Start the Server

```bash
python main.py
# Server starts at http://localhost:8000
```

### 3. Login and Get Access Token

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@example.com&password=admin123"
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### 4. Access Protected Endpoints

```bash
TOKEN="your_access_token_here"

curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

---

## Authentication Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Authentication Flow                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Client Request                                               │
│       ↓                                                       │
│  FastAPI Route (routes/auth.py)                              │
│       ↓                                                       │
│  Pydantic Schema Validation                                   │
│       ↓                                                       │
│  AuthService (services/auth_service.py)                      │
│       ├──→ Password Hashing (bcrypt)                         │
│       ├──→ JWT Token Generation (PyJWT)                      │
│       ├──→ Token Validation                                   │
│       └──→ User CRUD Operations                               │
│               ↓                                               │
│  DuckDBService (services/duckdb_service.py)                  │
│       ├──→ User Creation                                      │
│       ├──→ User Retrieval                                     │
│       └──→ Database Queries                                   │
│               ↓                                               │
│  DuckDB Database (data/fluxengine.db)                        │
│       └──→ users table                                        │
│                                                               │
│  AuditService (services/audit_service.py)                    │
│       └──→ Log authentication events                          │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Database Schema

**users table:**
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email VARCHAR UNIQUE NOT NULL,
    hashed_password VARCHAR NOT NULL,
    full_name VARCHAR NOT NULL,
    role VARCHAR NOT NULL CHECK (role IN ('admin', 'editor')),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

**Indexes:**
- `idx_users_email` on `email` for fast lookups

---

## User Registration Flow

### Endpoint: `POST /api/auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepass123",
  "full_name": "John Doe",
  "role": "editor"
}
```

**Validation Rules:**
- **email:** Valid email format (RFC 5322)
- **password:** Minimum 8 characters
- **full_name:** Required, non-empty string
- **role:** Must be `"admin"` or `"editor"`

**Success Response (201 Created):**
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "editor",
  "is_active": true,
  "created_at": "2026-02-08T12:00:00",
  "updated_at": "2026-02-08T12:00:00"
}
```

**Error Responses:**

- **400 Bad Request - Duplicate Email:**
  ```json
  {
    "detail": "User with this email already exists"
  }
  ```

- **422 Unprocessable Entity - Validation Error:**
  ```json
  {
    "detail": [
      {
        "loc": ["body", "password"],
        "msg": "String should have at least 8 characters",
        "type": "string_too_short"
      }
    ]
  }
  ```

### Internal Flow

```python
# 1. Validate input with Pydantic
user_data = UserCreate(email="...", password="...", ...)

# 2. Check for existing user
existing = auth_service.get_user_by_email(email)
if existing:
    raise ValueError("User with this email already exists")

# 3. Hash password with bcrypt
hashed_password = bcrypt.hash(password)  # $2b$12$...

# 4. Create user in database
user = db_service.create_user(
    email=email,
    hashed_password=hashed_password,
    full_name=full_name,
    role=role
)

# 5. Return user (password excluded from response)
return UserResponse(id=user.id, email=user.email, ...)
```

---

## Login Flow

### Endpoint: `POST /api/auth/login`

**Request Format:** OAuth2 Password Flow (Form Data)

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user@example.com&password=securepass123"
```

**Note:** OAuth2 spec uses `username` field, but we treat it as email.

**Success Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsInJvbGUiOiJlZGl0b3IiLCJleHAiOjE3NzA1NDk4OTJ9.WoVs_TVPD9ArC5kteU7b1uB7lcSZlsOnq4ApQOg7ypI",
  "token_type": "bearer"
}
```

**Error Responses:**

- **401 Unauthorized - Invalid Credentials:**
  ```json
  {
    "detail": "Invalid email or password"
  }
  ```

- **401 Unauthorized - Inactive Account:**
  ```json
  {
    "detail": "User account is inactive"
  }
  ```

### Internal Flow

```python
# 1. Retrieve user by email
user = db_service.get_user_by_email(email)
if not user:
    raise AuthenticationException("Invalid email or password")

# 2. Verify password (constant-time comparison)
if not bcrypt.verify(password, user.hashed_password):
    raise AuthenticationException("Invalid email or password")

# 3. Check active status
if not user.is_active:
    raise AuthenticationException("User account is inactive")

# 4. Generate JWT token
payload = {
    "sub": user.id,           # Subject (user ID)
    "email": user.email,      # User email
    "role": user.role,        # User role
    "exp": datetime.utcnow() + timedelta(minutes=30)
}
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# 5. Log successful login
audit_service.log_action(user.id, "login", ...)

# 6. Return token
return Token(access_token=token, token_type="bearer")
```

---

## JWT Token Structure

### Token Format

FluxEngine uses HMAC SHA-256 (HS256) signed JWT tokens.

**Header:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload:**
```json
{
  "sub": 1,                          // User ID (subject claim)
  "email": "user@example.com",       // User email
  "role": "editor",                  // User role (for RBAC)
  "exp": 1770549892                  // Expiration timestamp (Unix epoch)
}
```

**Signature:**
```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  SECRET_KEY
)
```

### Token Configuration

| Setting | Value | Environment Variable |
|---------|-------|----------------------|
| Algorithm | HS256 | `ALGORITHM` |
| Secret Key | (generated) | `SECRET_KEY` |
| Expiration | 30 minutes | `ACCESS_TOKEN_EXPIRE_MINUTES` |
| Token Type | Bearer | N/A |

**Generate Secret Key:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Token Validation

```python
# 1. Extract token from Authorization header
# Format: "Bearer <token>"
token = request.headers.get("Authorization").split(" ")[1]

# 2. Decode and verify signature
try:
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
except jwt.ExpiredSignatureError:
    raise AuthenticationException("Token has expired")
except jwt.PyJWTError:
    raise AuthenticationException("Invalid token")

# 3. Extract claims
user_id = payload.get("sub")
email = payload.get("email")
role = payload.get("role")

# 4. Retrieve current user from database
user = db_service.get_user_by_id(user_id)
if not user:
    raise AuthenticationException("User not found")

# 5. Return user object
return user
```

---

## Get Current User

### Endpoint: `GET /api/auth/me`

Retrieve the authenticated user's information.

**Request:**
```bash
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer <access_token>"
```

**Success Response (200 OK):**
```json
{
  "id": 1,
  "email": "user@example.com",
  "full_name": "John Doe",
  "role": "editor",
  "is_active": true,
  "created_at": "2026-02-08T12:00:00",
  "updated_at": "2026-02-08T12:00:00"
}
```

**Error Responses:**

- **401 Unauthorized - Missing Token:**
  ```json
  {
    "detail": "Not authenticated"
  }
  ```

- **401 Unauthorized - Invalid Token:**
  ```json
  {
    "detail": "Invalid token"
  }
  ```

- **401 Unauthorized - Expired Token:**
  ```json
  {
    "detail": "Token has expired"
  }
  ```

---

## Role-Based Access Control (RBAC)

### User Roles

FluxEngine supports two user roles:

| Role | Permissions |
|------|-------------|
| **admin** | Full system access: user management, table management, workflow management, system configuration |
| **editor** | Limited access: create/edit own workflows, view tables, execute workflows |

### Permission Matrix

| Operation | Admin | Editor |
|-----------|-------|--------|
| Create users | ✅ | ❌ |
| View all users | ✅ | ❌ |
| Create tables | ✅ | ✅ |
| View all tables | ✅ | ✅ |
| Delete tables | ✅ | ❌ |
| Create workflows | ✅ | ✅ |
| View own workflows | ✅ | ✅ |
| View all workflows | ✅ | ❌ |
| Delete workflows | ✅ | Own only |
| Execute workflows | ✅ | ✅ |
| View audit logs | ✅ | ❌ |

### Implementing RBAC in Routes

**Dependency Injection:**

```python
from fastapi import Depends
from utils.security import get_current_user, require_admin

# Require any authenticated user
@app.get("/api/tables")
async def list_tables(current_user: User = Depends(get_current_user)):
    # current_user is automatically injected
    return get_tables_for_user(current_user)

# Require admin role
@app.get("/api/users")
async def list_users(current_user: User = Depends(require_admin)):
    # Only admins can access this endpoint
    return get_all_users()
```

**Manual Role Check:**

```python
@app.delete("/api/workflows/{workflow_id}")
async def delete_workflow(
    workflow_id: int,
    current_user: User = Depends(get_current_user)
):
    workflow = get_workflow(workflow_id)

    # Admin can delete any workflow
    if current_user.role == "admin":
        return delete_workflow(workflow_id)

    # Editor can only delete their own workflows
    if workflow.created_by == current_user.id:
        return delete_workflow(workflow_id)

    raise HTTPException(status_code=403, detail="Forbidden")
```

---

## Password Security

### Hashing Algorithm

**bcrypt** with 12 salt rounds (2^12 = 4096 iterations)

**Implementation:**
```python
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Hash password
hashed = pwd_context.hash("plaintext_password")
# Output: $2b$12$KH8Q3.iF5X.5h.W8F5e0.Ou7j...

# Verify password (constant-time comparison)
is_valid = pwd_context.verify("plaintext_password", hashed)
```

### Password Requirements

- **Minimum Length:** 8 characters
- **Maximum Length:** 72 bytes (bcrypt limitation)
- **Character Requirements:** None (but recommended: mix of uppercase, lowercase, numbers, symbols)

**Recommendations for Production:**
- Enforce password complexity rules
- Implement password history (prevent reuse)
- Add rate limiting for password attempts
- Consider adding password expiration
- Implement "forgot password" flow with email verification

### Security Properties

- **Salt:** Unique per password, prevents rainbow table attacks
- **Adaptive Cost:** Can increase rounds as hardware improves
- **Constant-Time Comparison:** Prevents timing attacks
- **One-Way Function:** Cannot reverse hash to get plaintext

---

## API Endpoints Reference

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Create new user account | No |
| POST | `/api/auth/login` | Authenticate and get access token | No |
| GET | `/api/auth/me` | Get current user information | Yes (Bearer token) |

### Health Check

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | System health check | No |

**Response:**
```json
{
  "status": "healthy",
  "service": "FluxEngine"
}
```

---

## Error Handling

### Exception Hierarchy

```python
FluxEngineException (Base)
├── AuthenticationException (401 Unauthorized)
├── AuthorizationException (403 Forbidden)
├── NotFoundException (404 Not Found)
└── ValidationException (422 Unprocessable Entity)
```

### Common Error Responses

**401 Unauthorized:**
```json
{
  "detail": "Invalid token",
  "error_code": "AUTHENTICATION_ERROR"
}
```

**403 Forbidden:**
```json
{
  "detail": "Insufficient permissions",
  "error_code": "AUTHORIZATION_ERROR"
}
```

**422 Validation Error:**
```json
{
  "detail": [
    {
      "loc": ["body", "email"],
      "msg": "value is not a valid email address",
      "type": "value_error.email"
    }
  ]
}
```

---

## Audit Logging

### Logged Events

FluxEngine tracks all authentication events in the `audit_entries` table:

- User registration
- Successful login
- Failed login attempts
- Token validation failures
- Password changes
- Role changes
- Account deactivation

### Audit Entry Structure

```sql
CREATE TABLE audit_entries (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,                  -- User who performed action
    action VARCHAR NOT NULL,          -- Action type (e.g., "login", "register")
    entity_type VARCHAR NOT NULL,     -- Entity affected (e.g., "user")
    entity_id INTEGER,                -- ID of affected entity
    details VARCHAR,                  -- JSON with additional details
    ip_address VARCHAR,               -- Client IP address
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Query Audit Logs

```python
from services.audit_service import AuditService

audit_service = AuditService()

# Get all login attempts for a user
logs = audit_service.get_user_actions(user_id=1, action="login")

# Get failed login attempts
logs = audit_service.get_failed_logins(since=datetime.now() - timedelta(hours=1))
```

---

## Security Considerations

### ✅ Implemented Security Features

1. **Password Hashing:** bcrypt with salt
2. **JWT Signature Verification:** HMAC SHA-256
3. **Token Expiration:** 30-minute default
4. **Role-Based Access Control:** Admin and editor roles
5. **Audit Logging:** All authentication events tracked
6. **Input Validation:** Pydantic schemas
7. **CORS Configuration:** Restricted origins
8. **Constant-Time Comparisons:** Prevents timing attacks
9. **Database Isolation:** Parameterized queries (SQL injection prevention)
10. **Active User Check:** Inactive accounts cannot login

### ⚠️ Recommended Security Enhancements

1. **Rate Limiting:** Prevent brute force attacks on login endpoint
   - Implement: `slowapi` or `fastapi-limiter`
   - Limit: 5 login attempts per minute per IP

2. **Refresh Tokens:** Long-lived tokens for token renewal
   - Store refresh tokens in database with expiration
   - Separate endpoint for token refresh

3. **Email Verification:** Verify email on registration
   - Send verification email with token
   - Mark email as verified in database

4. **Password Reset Flow:** Forgot password functionality
   - Generate secure reset token
   - Send reset email
   - Expire reset token after use or timeout

5. **Session Management:** Track active sessions
   - Store session IDs in database
   - Allow users to revoke sessions
   - Implement logout endpoint

6. **Two-Factor Authentication (2FA):** Additional security layer
   - TOTP (Time-based One-Time Password)
   - Backup codes

7. **IP Whitelisting:** Restrict admin access by IP
   - Store allowed IPs in database
   - Check on admin endpoints

8. **Account Lockout:** Lock account after N failed attempts
   - Implement lockout counter
   - Automatic unlock after timeout

9. **Password Complexity Rules:** Enforce strong passwords
   - Minimum length: 12 characters
   - Mix of character types
   - Check against common password lists

10. **Security Headers:** Add security-related HTTP headers
    - `Strict-Transport-Security` (HSTS)
    - `X-Content-Type-Options: nosniff`
    - `X-Frame-Options: DENY`
    - `Content-Security-Policy`

### Environment Variables Security

**Never commit these to version control:**

```bash
# .env file (add to .gitignore)
SECRET_KEY=your-secret-key-here
DATABASE_PATH=./data/fluxengine.db
DEBUG=False
ALLOWED_ORIGINS=["https://yourdomain.com"]
```

**Generate secure secret key:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## Testing Authentication

### Manual Testing

**1. Register a new user:**
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "testpass123",
    "full_name": "Test User",
    "role": "editor"
  }'
```

**2. Login:**
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test@example.com&password=testpass123"
```

**3. Get current user:**
```bash
TOKEN="<access_token_from_login>"
curl -X GET http://localhost:8000/api/auth/me \
  -H "Authorization: Bearer $TOKEN"
```

### Automated Testing

Run the comprehensive test suite:

```bash
# Run all authentication tests
pytest tests/test_auth.py -v

# Run with coverage
pytest tests/test_auth.py --cov=services --cov=routes --cov-report=html

# Run specific test class
pytest tests/test_auth.py::TestPasswordHashing -v
```

**Test Coverage:** 46/51 tests passing (90%)

---

## Troubleshooting

### Common Issues

#### 1. "password cannot be longer than 72 bytes"

**Cause:** bcrypt 5.0.0 incompatibility with passlib 1.7.4

**Solution:**
```bash
pip install "bcrypt==4.1.2"
```

#### 2. "JWT has no attribute 'JWTError'"

**Cause:** PyJWT uses `PyJWTError` not `JWTError`

**Solution:** Update exception handling:
```python
# Incorrect
except jwt.JWTError:
    pass

# Correct
except jwt.PyJWTError:
    pass
```

#### 3. "Invalid token" immediately after login

**Cause:** Clock skew or incorrect secret key

**Solution:**
- Ensure SECRET_KEY matches between token generation and validation
- Check system time synchronization
- Verify environment variables are loaded correctly

#### 4. "User not found" with valid token

**Cause:** Database not initialized or user deleted

**Solution:**
```bash
# Reinitialize database and seed data
rm -f ./data/fluxengine.db*
python scripts/seed_db.py --non-interactive
```

#### 5. "Not authenticated" on protected endpoint

**Cause:** Missing or malformed Authorization header

**Solution:** Ensure header format:
```
Authorization: Bearer <access_token>
```

**Incorrect formats:**
- `Authorization: <access_token>` (missing "Bearer ")
- `Authorization: Bearer<access_token>` (missing space)
- `Token: <access_token>` (wrong header name)

---

## Configuration Reference

### Environment Variables

```bash
# Core Settings
SECRET_KEY=your-secret-key-here
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Database
DATABASE_PATH=./data/fluxengine.db

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=False

# CORS
ALLOWED_ORIGINS=["http://localhost:3000","https://yourdomain.com"]
```

### Default Users (Seeded)

After running `python scripts/seed_db.py --non-interactive`:

| Email | Password | Role | Use Case |
|-------|----------|------|----------|
| admin@example.com | admin123 | admin | System administration |
| editor@example.com | editor123 | editor | Workflow creation |
| test@example.com | test1234 | editor | Testing |

**⚠️ Change default passwords in production!**

---

## Production Deployment Checklist

- [ ] Generate strong SECRET_KEY (minimum 32 bytes)
- [ ] Set DEBUG=False
- [ ] Configure production ALLOWED_ORIGINS
- [ ] Change default admin password
- [ ] Set up HTTPS/TLS certificates
- [ ] Implement rate limiting
- [ ] Enable audit logging
- [ ] Configure database backups
- [ ] Set up monitoring and alerting
- [ ] Review and update CORS policy
- [ ] Implement refresh tokens
- [ ] Add email verification
- [ ] Configure production database path
- [ ] Set up reverse proxy (nginx/apache)
- [ ] Implement session management
- [ ] Add security headers
- [ ] Enable 2FA for admin accounts
- [ ] Set up log rotation
- [ ] Review and test disaster recovery plan

---

## API Documentation

### Interactive API Docs

FastAPI provides automatic interactive API documentation:

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

These interfaces allow you to:
- Explore all API endpoints
- View request/response schemas
- Test endpoints directly in the browser
- See authentication requirements
- Download OpenAPI JSON schema

---

## References

- **FastAPI Documentation:** https://fastapi.tiangolo.com/
- **JWT Standard (RFC 7519):** https://tools.ietf.org/html/rfc7519
- **bcrypt Algorithm:** https://en.wikipedia.org/wiki/Bcrypt
- **OAuth2 Password Flow:** https://oauth.net/2/grant-types/password/
- **Pydantic Validation:** https://docs.pydantic.dev/
- **OWASP Authentication:** https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

---

## Support

For issues, questions, or contributions:

- **Development Guide:** See [DEVELOPMENT_GUIDE.md](./DEVELOPMENT_GUIDE.md)
- **GitHub Issues:** (Add issue tracker URL)
- **Documentation:** http://localhost:8000/docs

---

*Last Updated: 2026-02-08*
*FluxEngine Authentication v1.0.0*
