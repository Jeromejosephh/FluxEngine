"""DuckDB database service"""
import duckdb
from typing import List, Dict, Any, Optional
from pathlib import Path

from utils.config import settings


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
