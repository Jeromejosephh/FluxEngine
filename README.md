# FluxEngine - Workflow Engine Backend

A production-ready workflow engine backend built with FastAPI, DuckDB, and modern Python practices.

## 🚀 Features

- **FastAPI** - Modern, fast web framework for building APIs
- **DuckDB** - Embedded analytical database for high performance
- **JWT Authentication** - Secure token-based authentication
- **Role-Based Access Control** - Admin and Editor roles with granular permissions
- **Audit Logging** - Comprehensive audit trail for all actions
- **Modular Architecture** - Clean separation of concerns
- **Type Safety** - Full type hints with Pydantic models
- **Production Ready** - Error handling, logging, and configuration management

## 📁 Project Structure

```
FluxEngine/
├── main.py                 # Application entry point
├── models/                 # Data models
│   ├── user.py
│   ├── table.py
│   ├── workflow.py
│   ├── step.py
│   └── audit.py
├── schemas/                # Pydantic schemas
│   ├── user.py
│   ├── table.py
│   ├── workflow.py
│   ├── step.py
│   └── auth.py
├── routes/                 # API endpoints
│   ├── auth.py
│   ├── tables.py
│   └── workflows.py
├── services/               # Business logic
│   ├── auth_service.py
│   ├── duckdb_service.py
│   └── audit_service.py
├── utils/                  # Utilities
│   ├── security.py
│   ├── config.py
│   └── exceptions.py
├── tests/                  # Test suite
│   ├── test_auth.py
│   └── test_tables.py
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variables template
└── README.md              # This file
```

## 🛠️ Setup & Installation

### Prerequisites

- Python 3.11 or higher
- pip (Python package manager)

### Installation Steps

1. **Clone or navigate to the project directory**
   ```bash
   cd FluxEngine
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   ```

3. **Activate the virtual environment**
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```

4. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set your configuration:
   - Generate a secure `SECRET_KEY`: `openssl rand -hex 32`
   - Adjust other settings as needed

6. **Seed the database with initial data**
   ```bash
   # Non-interactive mode (uses default credentials)
   python scripts/seed_db.py --non-interactive

   # Interactive mode (prompts for admin credentials)
   python scripts/seed_db.py

   # Admin only (no sample data)
   python scripts/seed_db.py --admin-only

   # Reset database (drop and recreate)
   python scripts/seed_db.py --force
   ```

   **Default Credentials (Non-Interactive):**
   - Email: `admin@example.com`
   - Password: `admin123`
   - Role: `admin`

## 🚀 Running the Application

### Development Server

Run the development server with auto-reload:

```bash
python main.py
```

Or using uvicorn directly:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at: `http://localhost:8000`

### Initialize Database

The database is automatically initialized on first run. The schema includes:
- Users table (with authentication)
- Tables table (data table definitions)
- Workflows table (workflow definitions)
- Steps table (workflow steps)
- Audit entries table (audit logging)

### API Documentation

FastAPI automatically generates interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Additional Documentation

- **Authentication Guide**: See [AUTH.md](./AUTH.md) for comprehensive authentication documentation
- **Development Guide**: See [DEVELOPMENT_GUIDE.md](./DEVELOPMENT_GUIDE.md) for project roadmap and architecture

## 🧪 Running Tests

Run the test suite:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=. --cov-report=html
```

Run specific test file:

```bash
pytest tests/test_auth.py -v
```

## 📚 API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and get JWT token
- `GET /api/auth/me` - Get current user info

### Tables
- `GET /api/tables/` - List all tables
- `GET /api/tables/{id}` - Get table by ID
- `POST /api/tables/` - Create a new table (requires: editor/admin)
- `PUT /api/tables/{id}` - Update table (requires: editor/admin)
- `DELETE /api/tables/{id}` - Delete table (requires: admin)

### Workflows
- `GET /api/workflows/` - List all workflows
- `GET /api/workflows/{id}` - Get workflow by ID
- `POST /api/workflows/` - Create a new workflow (requires: editor/admin)
- `PUT /api/workflows/{id}` - Update workflow (requires: editor/admin)
- `DELETE /api/workflows/{id}` - Delete workflow (requires: admin)
- `POST /api/workflows/{id}/steps` - Add step to workflow
- `GET /api/workflows/{id}/steps` - List workflow steps

## 🔐 Authentication & Authorization

### Roles
- **Admin**: Full access to all resources
- **Editor**: Can create and edit tables and workflows
- **User**: Read-only access (future)

### Using the API

1. **Register a user**
   ```bash
   curl -X POST "http://localhost:8000/api/auth/register" \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "securepass123",
       "full_name": "John Doe",
       "role": "editor"
     }'
   ```

2. **Login to get token**
   ```bash
   curl -X POST "http://localhost:8000/api/auth/login" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=user@example.com&password=securepass123"
   ```

3. **Use token in requests**
   ```bash
   curl -X GET "http://localhost:8000/api/tables/" \
     -H "Authorization: Bearer YOUR_TOKEN_HERE"
   ```

## 🔧 Development

### Code Style

Format code with Black:
```bash
black .
```

Lint with Flake8:
```bash
flake8 .
```

Type checking with mypy:
```bash
mypy .
```

### Adding New Features

1. Add models in `models/`
2. Add Pydantic schemas in `schemas/`
3. Add business logic in `services/`
4. Add API endpoints in `routes/`
5. Write tests in `tests/`

## 📝 TODO

- [ ] Implement complete CRUD operations for all entities
- [ ] Add workflow execution engine
- [ ] Add temporal/scheduled workflow support
- [ ] Add webhook support
- [ ] Add rate limiting
- [ ] Add comprehensive logging
- [ ] Add database migrations
- [ ] Add data export/import
- [ ] Add API versioning
- [ ] Add WebSocket support for real-time updates
- [ ] Add email notifications
- [ ] Add user management UI
- [ ] Add API key authentication
- [ ] Add OAuth2 support

## 📄 License

MIT License - feel free to use this project for any purpose.

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

For issues or questions, please create an issue in the repository.

---

**Built with ❤️ using FastAPI and DuckDB**
