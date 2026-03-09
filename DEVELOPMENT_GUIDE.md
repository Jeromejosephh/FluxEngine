# FluxEngine Development Guide

**Last Updated:** 2026-03-09 (All 93 tests passing — MVP Complete)
**Project Status:** MVP Complete ✅
**Current Phase:** Advanced Features + Production Readiness

---

## General Work Plan

FluxEngine is a workflow automation engine with a Python/FastAPI backend and DuckDB persistence layer. The development follows a phased approach, building from core infrastructure to advanced workflow execution capabilities.

**Core Principles:**
- **API-First Design:** RESTful endpoints with OpenAPI documentation
- **Security First:** JWT authentication, role-based access control, comprehensive audit logging
- **Database-Driven:** DuckDB for lightweight, embedded SQL persistence
- **Modular Architecture:** Clear separation between services, routes, models, and schemas
- **Test Coverage:** Unit and integration tests for all critical paths

**Technology Stack:**
- **Backend:** Python 3.9+, FastAPI, Uvicorn
- **Database:** DuckDB (embedded SQL database)
- **Authentication:** JWT (PyJWT), bcrypt password hashing (passlib)
- **Validation:** Pydantic schemas
- **Testing:** pytest, FastAPI TestClient

---

## Implementation Stages

### Stage 1: Foundation (Complete) ✅ 100%
**Objective:** Establish core backend infrastructure, authentication, and database layer.

**Components:**
- Database schema design with DuckDB
- User authentication and authorization system
- JWT token-based session management
- Role-based access control (admin/editor)
- Audit logging infrastructure
- Basic API routes structure

**Status:**
- ✅ Database service with auto-incrementing sequences
- ✅ User CRUD operations
- ✅ Password hashing with bcrypt 4.1.2
- ✅ JWT token generation and validation
- ✅ Authentication endpoints (register, login, /me)
- ✅ Exception handling framework
- ✅ Comprehensive test coverage (51/51 tests passing, 100%)
- ✅ Database seeding script with admin user creation
- ✅ Complete authentication documentation (AUTH.md)

---

### Stage 2: Table Management (Complete) ✅ 100%
**Objective:** Implement dynamic table creation, schema management, and data operations.

**Components:**
- Table creation with custom schemas
- Column type validation and constraints
- Table metadata management
- Access control per table
- CRUD operations for table metadata

**Status:**
- ✅ Database schema for tables metadata
- ✅ UNIQUE index on table names (case-insensitive)
- ✅ DuckDB table CRUD methods (6 methods)
- ✅ TableService with validation (7 methods)
- ✅ Schema validation (types, naming, uniqueness)
- ✅ All 5 API endpoints implemented (GET, POST, PUT, DELETE)
- ✅ Audit logging for all operations
- ✅ Manual tests passing (8/8 tests)
- ✅ Reserved name validation
- ✅ RBAC enforcement (admin/editor)

---

### Stage 3: Workflow Engine (Complete) ✅ 100%
**Objective:** Build the workflow execution engine with step orchestration.

**Components:**
- Workflow creation and management
- Step definition (query, transform, condition, action)
- Step execution engine
- Workflow state management
- Error handling and retry logic

**Status:**
- ✅ Database schema for workflows and steps
- ✅ Workflow CRUD DB methods (create, get, list, update, soft delete)
- ✅ Step CRUD DB methods (create, get by workflow, get by id)
- ✅ WorkflowService with validation and CRUD
- ✅ StepService with per-type config validation
- ✅ Physical table data storage (insert rows, query rows with filters)
- ✅ Table data endpoints (POST /tables/{id}/data, GET /tables/{id}/data)
- ✅ ExecutionService — runs steps sequentially, passes output as context
- ✅ Query step handler — filters rows from a managed table
- ✅ Transform step handler — column projection + row filtering in Python
- ✅ All workflow API endpoints (list, get, create, update, delete)
- ✅ Step API endpoints (create step, list steps)
- ✅ POST /api/workflows/{id}/run — executes workflow, returns per-step results
- ✅ Audit logging for all workflow and step operations
- ✅ Fixed DuckDB partial index IF NOT EXISTS bug on startup
- ✅ Fixed DuckDB 0.10.0 ART index bug (removed idx_workflows_status — UPDATE on indexed column triggers false PK violation)
- ✅ 28/28 workflow tests passing

---

### Stage 4: Advanced Features 🔄 ~43% Complete
**Objective:** Add advanced capabilities for production readiness.

**Components:**
- Workflow templates library
- Real-time execution monitoring
- Workflow analytics and metrics
- Email/webhook notifications
- API rate limiting
- Caching layer (Redis optional)
- Database backup/restore

**Status:**
- ✅ Table row update endpoint (`PUT /api/tables/{id}/data/{row_id}`)
- ✅ Table row delete endpoint (`DELETE /api/tables/{id}/data/{row_id}`)
- ✅ Column validation and 404 handling for row mutations
- ✅ 14/14 table tests passing
- ✅ Real-time execution monitoring (`executions` table + `GET /api/workflows/{id}/runs`)
- ✅ Execution records persist per-step metadata, row counts, success/error state
- ✅ 28/28 workflow tests passing
- ⏳ Action step type (webhook POST)
- ⏳ Workflow scheduling (APScheduler)
- ✅ API rate limiting (slowapi — 10/minute on `/run`, shared limiter, disabled in tests)
- ⏳ Caching layer
- ⏳ Database backup/restore

---

### Stage 5: Production Readiness 🔄 ~13% Complete
**Objective:** Prepare system for production deployment.

**Components:**
- Comprehensive test suite (>80% coverage)
- Performance optimization and profiling
- Docker containerization
- CI/CD pipeline setup
- Production configuration management
- Monitoring and observability (logging, metrics)
- Documentation (API docs, deployment guide)
- Security audit and hardening

**Status:**
- ✅ Dockerfile (python:3.9-slim, exposes port 8000)
- ✅ .dockerignore (excludes venv, data, .env, caches)
- ✅ .env.example with all required variables
- ✅ .gitignore covers .env, data/, .venv
- ✅ CI/CD pipeline (GitHub Actions — runs on push/PR to main)
- ⏳ >80% test coverage
- ⏳ Performance optimization
- ⏳ Security audit
- ⏳ Deployment guide

---

## Checklist

### Phase 1: Foundation ✅
- [x] Set up project structure
- [x] Configure DuckDB service
- [x] Implement database schema with sequences
- [x] Create User model and schemas
- [x] Implement password hashing (bcrypt 4.1.2)
- [x] Implement JWT token generation
- [x] Implement user authentication service
- [x] Create authentication endpoints
- [x] Implement role-based access control
- [x] Set up audit logging service
- [x] Configure CORS and middleware
- [x] Create exception handling framework
- [x] Write authentication tests (51 tests, 90% passing)
- [x] Fix bcrypt 5.0 compatibility issue
- [x] Fix DuckDB auto-increment sequences
- [x] Create database seeding script
- [x] Document authentication flow

### Phase 2: Table Management ✅
- [x] Define table metadata schema
- [x] Create table API routes structure
- [x] Implement table creation service (TableService)
- [x] Implement schema validation logic (7 validation rules)
- [x] Create table CRUD endpoints (5 endpoints)
- [x] Add UNIQUE index on table names
- [x] Add table access control (RBAC)
- [x] Write table management tests (8 manual tests passing)
- [x] Fix DuckDB UPDATE bug (dynamic query builder)
- [x] Implement data insertion endpoint (POST /api/tables/{id}/data)
- [x] Implement data query endpoint (GET /api/tables/{id}/data)
- [x] API documented via auto-generated Swagger UI at /docs

### Phase 3: Workflow Engine ✅
- [x] Define workflow/step schema
- [x] Create workflow API routes structure
- [x] Implement workflow service (WorkflowService)
- [x] Implement step service (StepService) with config validation
- [x] Create workflow execution engine (ExecutionService)
- [x] Implement step type handlers — query and transform
- [x] Add workflow state management (draft / active / archived)
- [x] Implement error handling (step failure stops pipeline, error surfaced in response)
- [x] Create workflow CRUD endpoints (list, get, create, update, delete)
- [x] Add step CRUD endpoints (create step, list steps)
- [x] Add workflow execution endpoint (POST /run)
- [x] Add table data endpoints (insert rows, query rows)
- [x] Fix DuckDB partial index startup crash
- [x] Write workflow execution tests

### Phase 4: Advanced Features
- [x] Implement table row update endpoint (PUT /api/tables/{id}/data/{row_id})
- [x] Implement table row delete endpoint (DELETE /api/tables/{id}/data/{row_id})
- [x] Implement real-time monitoring (executions table + GET /api/workflows/{id}/runs)
- [ ] Implement action step type (webhook POST)
- [ ] Implement workflow scheduling (APScheduler)
- [x] Add API rate limiting (slowapi — 10/minute on /run endpoint)
- [ ] Create workflow templates
- [ ] Add workflow analytics
- [ ] Configure caching layer
- [ ] Implement backup/restore

### Phase 5: Production
- [x] Create Dockerfile
- [x] Create .dockerignore
- [x] Create .env.example
- [x] Set up CI/CD pipeline (GitHub Actions)
- [ ] Configure production environment
- [ ] Achieve >80% test coverage
- [ ] Performance optimization
- [ ] Implement monitoring/logging
- [ ] Complete API documentation
- [ ] Security audit
- [ ] Deployment guide

---

## Progress Overview

```
Overall Project Completion: ~80% (MVP Complete)

┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Foundation           ██████████ 100% ✅            │
│ Stage 2: Table Management     ██████████ 100% ✅            │
│ Stage 3: Workflow Engine      ██████████ 100% ✅            │
│ Stage 4: Advanced Features    ████░░░░░░  43% 🔄            │
│ Stage 5: Production Readiness ████░░░░░░  40% 🔄            │
└─────────────────────────────────────────────────────────────┘

Legend: ✅ Complete  🔄 Partially Started  ⏳ Not Started
```

### Completed Components
- ✅ DuckDB integration with auto-incrementing sequences
- ✅ User authentication (register, login, JWT)
- ✅ Password hashing with bcrypt 4.1.2
- ✅ Role-based access control (admin/editor)
- ✅ Audit logging infrastructure
- ✅ Exception handling framework
- ✅ CORS configuration
- ✅ Database schema for all entities
- ✅ Authentication test suite (51 tests, 46 passing)
- ✅ Database fixtures and test isolation
- ✅ Database seeding script (scripts/seed_db.py)
- ✅ Complete authentication documentation (AUTH.md)
- ✅ Table metadata management (TableService)
- ✅ Table CRUD operations with validation
- ✅ Schema validation (column types, naming, uniqueness)
- ✅ Table API endpoints (list, get, create, update, delete)
- ✅ Case-insensitive unique table names
- ✅ Reserved name protection
- ✅ Table row update (`PUT /api/tables/{id}/data/{row_id}`)
- ✅ Table row delete (`DELETE /api/tables/{id}/data/{row_id}`)
- ✅ Execution history (`executions` table, `GET /api/workflows/{id}/runs`)
- ✅ Per-step metadata persisted on every workflow run (no output bloat)

### In Progress
- Stage 4: Advanced Features (row mutations, monitoring, rate limiting complete; action steps, scheduling pending)
- Stage 5: Production Readiness (Docker done; CI/CD, test coverage, security audit pending)

### Recently Completed
- ✅ All 93 tests passing (51 auth + 14 table + 28 workflow) — 100% pass rate
- ✅ Fixed RBAC: `require_admin`/`require_editor` made async, now correctly resolve user via FastAPI dependency injection
- ✅ Fixed JWT timezone bug: test now uses `timezone.utc` on both sides
- ✅ GitHub Actions CI — `.github/workflows/test.yml`, runs pytest on push/PR to main
- ✅ Dockerfile — `python:3.9-slim`, installs deps, exposes port 8000
- ✅ `.dockerignore` — excludes venv, data dir, .env, caches
- ✅ API rate limiting: 10/minute on `/run`, shared `utils/limiter.py`, disabled in tests via `conftest.py`
- ✅ Real-time monitoring: `executions` table persists every workflow run
- ✅ `GET /api/workflows/{id}/runs` — paginated execution history, newest first
- ✅ Table row update: `PUT /api/tables/{id}/data/{row_id}` with column validation
- ✅ Table row delete: `DELETE /api/tables/{id}/data/{row_id}` with 404 guard

### Recently Fixed
- ✅ RBAC coroutine bug — `require_admin`/`require_editor` returned unawaited coroutine; fixed by making them `async def` with `await`
- ✅ JWT timing test — `datetime.fromtimestamp()` vs `datetime.utcnow()` timezone mismatch; fixed with `timezone.utc`
- ✅ bcrypt 5.0.0 → 4.1.2 compatibility issue
- ✅ DuckDB sequences for auto-increment IDs
- ✅ JWT PyJWTError exception handling
- ✅ Test database isolation with temporary files
- ✅ DuckDB UPDATE with COALESCE causing PK constraint violation (replaced with dynamic query builder)
- ✅ DuckDB partial index IF NOT EXISTS not respected on reconnect (wrapped in try/except)
- ✅ DuckDB 0.10.0 ART index bug — UPDATE on any indexed column triggers false PK violation (removed idx_workflows_status)
- ✅ `datetime.utcnow()` deprecation — replaced with `datetime.now(timezone.utc)` in all update methods

### Blocked/Issues
- ⚠️ bcrypt 5.0.0 incompatible with passlib 1.7.4 (resolved: downgraded to 4.1.2)
- ⚠️ DuckDB requires explicit sequences for auto-increment (resolved)
- ⚠️ PyJWT uses `PyJWTError` not `JWTError` (resolved)
- ⚠️ DuckDB UPDATE with COALESCE on schema_definition causes PK violation (resolved: dynamic query builder)
- ⚠️ DuckDB 0.10.0 UPDATE on indexed column causes false PK violation (resolved: removed secondary index on status column)

---

## Next Actions

### MVP Complete ✅

All MVP items shipped. Next focus is post-MVP features.

### Post-MVP — Phase 4 Remainder

2. **Notification / Action Steps**
   - Implement `action` step type that POSTs results to a webhook URL
   - Add webhook URL config to step config schema

3. **Workflow Scheduling**
   - Trigger workflows on a cron schedule (e.g. APScheduler)
   - Store schedule config on the workflow model

4. **Testing & Quality**
   - Achieve 70%+ test coverage
   - Fix remaining auth test failures (RBAC fixture, JWT timing)

---

## Development Workflow

### Running the Application

```bash
# Install dependencies
pip install -r requirements.txt

# Run development server
python main.py

# Or with uvicorn directly
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Docker

```bash
# Build image
docker build -t fluxengine .

# Run container (pass env file, persist data volume)
docker run -p 8000:8000 \
  --env-file .env \
  -v $(pwd)/data:/app/data \
  fluxengine
```

### Database Management

```bash
# Initialize database (automatic on app startup)
python -c "from services.duckdb_service import DuckDBService; db = DuckDBService(); db.init_db()"

# Delete database (reset)
rm -f ./data/fluxengine.db*
```

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_auth.py -v
```

### Code Quality

```bash
# Format code
black .

# Lint code
flake8 .

# Type checking
mypy .
```

---

## Architecture Notes

### Directory Structure

```
FluxEngine/
├── main.py                 # FastAPI application entry point
├── models/                 # Data models (dataclasses)
│   ├── user.py
│   ├── table.py
│   ├── workflow.py
│   ├── step.py
│   └── execution.py
├── schemas/                # Pydantic validation schemas
│   ├── user.py
│   ├── auth.py
│   ├── table.py
│   ├── workflow.py
│   └── execution.py
├── services/               # Business logic layer
│   ├── duckdb_service.py
│   ├── auth_service.py
│   ├── audit_service.py
│   ├── table_service.py
│   ├── workflow_service.py
│   ├── step_service.py
│   └── execution_service.py
├── routes/                 # API endpoints
│   ├── auth.py
│   ├── tables.py
│   └── workflows.py
├── utils/                  # Utilities and configuration
│   ├── config.py
│   ├── exceptions.py
│   └── security.py
└── tests/                  # Test suite
    ├── test_auth.py
    ├── test_tables.py
    └── test_workflows.py
```

### Key Design Decisions

1. **DuckDB over PostgreSQL:** Chosen for simplicity, embedded deployment, and OLAP capabilities suitable for workflow data.

2. **JWT over Sessions:** Stateless authentication enables horizontal scaling and API-first architecture.

3. **Sequences for Auto-Increment:** DuckDB requires explicit sequences unlike SQLite's automatic rowid.

4. **Soft Deletes:** `is_active` flags instead of hard deletes for audit trail preservation.

5. **bcrypt 4.1.2:** Version pinned due to passlib compatibility issues with bcrypt 5.0+.

---

## Troubleshooting

### Common Issues

**Issue:** `password cannot be longer than 72 bytes`
**Solution:** Ensure bcrypt version is 4.1.2, not 5.0.0. Run: `pip install bcrypt==4.1.2`

**Issue:** `JWT has no attribute 'JWTError'`
**Solution:** Use `jwt.PyJWTError` instead of `jwt.JWTError` in exception handling.

**Issue:** `NOT NULL constraint failed: users.id`
**Solution:** Ensure database sequences are created. Drop and recreate database.

**Issue:** `ALLOWED_ORIGINS JSON decode error`
**Solution:** Format .env value as JSON array: `["http://localhost:3000"]`

**Issue:** Database locked
**Solution:** Only one connection to DuckDB database file at a time. Close other processes.

**Issue:** Pytest: "not a valid DuckDB database file" error
**Solution:** Don't create empty temp files. Use `mkstemp()` then `unlink()` to get path without file. Let DuckDB create the database file itself.

**Issue:** Test failures with "coroutine not awaited" in RBAC tests
**Solution:** FastAPI dependency injection pattern for async functions. Use `Depends()` correctly or refactor test fixtures.

---

## Test Coverage Summary

### Authentication Tests (`tests/test_auth.py`)

**Status:** 51/51 tests passing (100% pass rate) ✅

**Test Categories:**
- ✅ Password Hashing (4/4 tests)
- ✅ JWT Tokens (6/6 tests)
- ✅ User CRUD (6/6 tests)
- ✅ User Authentication (7/7 tests)
- ✅ Registration Endpoint (6/6 tests)
- ✅ Login Endpoint (6/6 tests)
- ✅ Get Current User (4/4 tests)
- ✅ RBAC (5/5 tests)
- ✅ Input Validation (3/3 tests)
- ✅ Security Edge Cases (3/3 tests)
- ✅ Health Check (1/1 test)

**Running Tests:**
```bash
# Run all tests
pytest tests/test_auth.py -v

# Run with coverage
pytest tests/test_auth.py --cov=services --cov=routes --cov-report=html

# Run specific test class
pytest tests/test_auth.py::TestPasswordHashing -v
```

---

### Table Tests (`tests/test_tables.py`)

**Status:** 14/14 tests passing (100% pass rate) ✅

**Test Categories:**
- ✅ Auth guards (4/4 tests) — list, create, update row, delete row without token
- ✅ Row update — success, multi-column, 404, unknown column, empty data, table not found (6/6)
- ✅ Row delete — success, 404, table not found, double-delete (4/4)

---

### Workflow Tests (`tests/test_workflows.py`)

**Status:** 28/28 tests passing (100% pass rate) ✅

**Test Categories:**
- ✅ Workflow CRUD (8/8 tests)
- ✅ Step CRUD (4/4 tests)
- ✅ Table data insert/query (2/2 tests)
- ✅ Workflow execution — query, transform, error cases (6/6 tests)
- ✅ Execution history — persist, paginate, auth, 404 (8/8 tests)

---

## Contributing Guidelines

1. **Branch Naming:** `feature/table-management`, `bugfix/auth-token-expiry`
2. **Commit Messages:** Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`
3. **Code Style:** Follow PEP 8, use black formatter, max line length 100
4. **Testing:** Write tests for all new features, maintain >70% coverage
5. **Documentation:** Update this guide when adding new stages or components

---

## Contact & Resources

- **Repository:** (Add GitHub URL)
- **Documentation:** `/docs` endpoint (FastAPI auto-generated)
- **Issue Tracker:** (Add issue tracker URL)
- **Project Lead:** (Add contact info)

---

*This document is maintained by the development team and should be updated as the project evolves.*
