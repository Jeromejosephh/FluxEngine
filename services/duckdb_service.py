"""DuckDB database service"""
import duckdb
from typing import List, Dict, Any, Optional
from pathlib import Path

from utils.config import settings
from models.user import User


class DuckDBService:
    """Service for DuckDB operations"""
    
    def __init__(self):
        """Initialize DuckDB connection"""
        self.db_path = settings.DATABASE_PATH
        self.conn = None
    
    def get_connection(self) -> duckdb.DuckDBPyConnection:
        """
        Get or create DuckDB connection
        
        Returns:
            DuckDB connection
        """
        if self.conn is None:
            # Ensure database directory exists
            db_dir = Path(self.db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)
            
            self.conn = duckdb.connect(self.db_path)
        
        return self.conn
    
    def execute(self, query: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
        """
        Execute a SQL query and return results
        
        Args:
            query: SQL query string
            params: Optional query parameters
            
        Returns:
            List of result rows as dictionaries
        """
        conn = self.get_connection()
        
        if params:
            result = conn.execute(query, params)
        else:
            result = conn.execute(query)
        
        # Convert to list of dictionaries
        columns = [desc[0] for desc in result.description] if result.description else []
        rows = result.fetchall()
        
        return [dict(zip(columns, row)) for row in rows]
    
    def execute_many(self, query: str, params_list: List[tuple]) -> None:
        """
        Execute a SQL query with multiple parameter sets
        
        Args:
            query: SQL query string
            params_list: List of parameter tuples
        """
        conn = self.get_connection()
        conn.executemany(query, params_list)
    
    def init_db(self) -> None:
        """
        Initialize database schema
        Creates all required tables if they don't exist
        """
        conn = self.get_connection()
        
        # Users table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                email VARCHAR UNIQUE NOT NULL,
                hashed_password VARCHAR NOT NULL,
                full_name VARCHAR NOT NULL,
                role VARCHAR NOT NULL CHECK (role IN ('admin', 'editor')),
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Tables table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tables (
                id INTEGER PRIMARY KEY,
                name VARCHAR NOT NULL,
                description VARCHAR,
                schema_definition VARCHAR NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        
        # Workflows table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS workflows (
                id INTEGER PRIMARY KEY,
                name VARCHAR NOT NULL,
                description VARCHAR,
                status VARCHAR NOT NULL CHECK (status IN ('draft', 'active', 'archived')),
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)
        
        # Steps table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS steps (
                id INTEGER PRIMARY KEY,
                workflow_id INTEGER NOT NULL,
                name VARCHAR NOT NULL,
                step_type VARCHAR NOT NULL CHECK (step_type IN ('query', 'transform', 'condition', 'action')),
                config VARCHAR NOT NULL,
                "order" INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (workflow_id) REFERENCES workflows(id)
            )
        """)
        
        # Audit entries table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_entries (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action VARCHAR NOT NULL,
                entity_type VARCHAR NOT NULL,
                entity_id INTEGER,
                details VARCHAR,
                ip_address VARCHAR,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        
        # Create indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tables_created_by ON tables(created_by)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_workflows_created_by ON workflows(created_by)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_steps_workflow_id ON steps(workflow_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_entries(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_entries(entity_type, entity_id)")
        
        conn.commit()
    
    def close(self) -> None:
        """Close database connection"""
        if self.conn:
            self.conn.close()
            self.conn = None

    # User methods

    def create_user(self, email: str, hashed_password: str, full_name: str, role: str) -> User:
        """
        Create a new user

        Args:
            email: User's email address
            hashed_password: Pre-hashed password
            full_name: User's full name
            role: User role ('admin' or 'editor')

        Returns:
            Created User object

        Raises:
            Exception: If email already exists or other database error
        """
        query = """
            INSERT INTO users (email, hashed_password, full_name, role, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            RETURNING id, email, hashed_password, full_name, role, is_active, created_at, updated_at
        """

        result = self.execute(query, (email, hashed_password, full_name, role))

        if not result:
            raise Exception("Failed to create user")

        row = result[0]
        return User(
            id=row['id'],
            email=row['email'],
            hashed_password=row['hashed_password'],
            full_name=row['full_name'],
            role=row['role'],
            is_active=row['is_active'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )

    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email address

        Args:
            email: User's email address

        Returns:
            User object if found, None otherwise
        """
        query = """
            SELECT id, email, hashed_password, full_name, role, is_active, created_at, updated_at
            FROM users
            WHERE email = ?
            LIMIT 1
        """

        result = self.execute(query, (email,))

        if not result:
            return None

        row = result[0]
        return User(
            id=row['id'],
            email=row['email'],
            hashed_password=row['hashed_password'],
            full_name=row['full_name'],
            role=row['role'],
            is_active=row['is_active'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID

        Args:
            user_id: User's ID

        Returns:
            User object if found, None otherwise
        """
        query = """
            SELECT id, email, hashed_password, full_name, role, is_active, created_at, updated_at
            FROM users
            WHERE id = ?
            LIMIT 1
        """

        result = self.execute(query, (user_id,))

        if not result:
            return None

        row = result[0]
        return User(
            id=row['id'],
            email=row['email'],
            hashed_password=row['hashed_password'],
            full_name=row['full_name'],
            role=row['role'],
            is_active=row['is_active'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )
