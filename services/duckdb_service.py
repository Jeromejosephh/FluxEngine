"""DuckDB database service"""
import duckdb
from typing import List, Dict, Any, Optional
from pathlib import Path

from utils.config import settings
from utils.exceptions import ValidationException, NotFoundException
from models.user import User
from models.table import Table
from models.workflow import Workflow
from models.step import Step
from models.execution import Execution
from models.schedule import Schedule
from models.template import WorkflowTemplate


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
            CREATE SEQUENCE IF NOT EXISTS seq_users_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_users_id'),
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
            CREATE SEQUENCE IF NOT EXISTS seq_tables_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS tables (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_tables_id'),
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
            CREATE SEQUENCE IF NOT EXISTS seq_workflows_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS workflows (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_workflows_id'),
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
            CREATE SEQUENCE IF NOT EXISTS seq_steps_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS steps (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_steps_id'),
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
            CREATE SEQUENCE IF NOT EXISTS seq_audit_entries_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_entries (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_audit_entries_id'),
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
        
        # Executions table
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_executions_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS executions (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_executions_id'),
                workflow_id INTEGER NOT NULL,
                workflow_name VARCHAR NOT NULL,
                success BOOLEAN NOT NULL,
                executed_at TIMESTAMP NOT NULL,
                executed_by INTEGER NOT NULL,
                error VARCHAR,
                step_count INTEGER NOT NULL,
                steps_json VARCHAR NOT NULL,
                final_output_count INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (workflow_id) REFERENCES workflows(id),
                FOREIGN KEY (executed_by) REFERENCES users(id)
            )
        """)

        # Schedules table
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_schedules_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_schedules_id'),
                workflow_id INTEGER NOT NULL UNIQUE,
                cron_expr VARCHAR NOT NULL,
                is_enabled BOOLEAN DEFAULT TRUE,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_run_at TIMESTAMP,
                next_run_at TIMESTAMP,
                FOREIGN KEY (workflow_id) REFERENCES workflows(id),
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)

        # Workflow templates table
        conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS seq_workflow_templates_id START 1
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS workflow_templates (
                id INTEGER PRIMARY KEY DEFAULT nextval('seq_workflow_templates_id'),
                name VARCHAR NOT NULL,
                description VARCHAR,
                tags VARCHAR NOT NULL DEFAULT '[]',
                step_configs VARCHAR NOT NULL,
                created_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        """)

        # Create indexes
        # Note: idx_workflows_status is intentionally omitted — DuckDB 0.10.0 has
        # an ART index bug where any UPDATE on an indexed column triggers a false
        # "Duplicate key" PK violation. Status is queried infrequently enough that
        # the missing index has no practical impact for MVP scale.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_tables_created_by ON tables(created_by)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_workflows_created_by ON workflows(created_by)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_steps_workflow_id ON steps(workflow_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_entries(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_entries(entity_type, entity_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_executions_workflow_id ON executions(workflow_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_schedules_workflow_id ON schedules(workflow_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_templates_created_by ON workflow_templates(created_by)")

        # Unique index on template name (case-insensitive) for active templates only
        try:
            conn.execute("""
                CREATE UNIQUE INDEX idx_templates_name_unique
                ON workflow_templates(LOWER(name))
                WHERE is_active = TRUE
            """)
        except Exception:
            pass  # Index already exists — safe to continue

        # Note: idx_tables_name_unique is intentionally omitted — DuckDB 0.10.0 has
        # an ART index bug where any UPDATE on an indexed column triggers a false
        # "Duplicate key" PK violation (same issue as idx_workflows_status).
        # Uniqueness is enforced at the service level via validate_table_name().

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

    # Table methods

    def create_table_metadata(
        self,
        name: str,
        description: Optional[str],
        schema_definition: str,
        created_by: int
    ) -> Table:
        """
        Create table metadata entry

        Args:
            name: Table name
            description: Optional table description
            schema_definition: JSON string of column definitions
            created_by: User ID who created the table

        Returns:
            Created Table object

        Raises:
            Exception: If table name already exists or database error
        """
        query = """
            INSERT INTO tables (name, description, schema_definition, created_by, created_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
            RETURNING id, name, description, schema_definition, created_by, created_at, updated_at, is_active
        """

        result = self.execute(query, (name, description, schema_definition, created_by))

        if not result:
            raise Exception("Failed to create table")

        row = result[0]
        return Table(
            id=row['id'],
            name=row['name'],
            description=row['description'],
            schema_definition=row['schema_definition'],
            created_by=row['created_by'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            is_active=row['is_active']
        )

    def get_table_by_id(self, table_id: int) -> Optional[Table]:
        """
        Get table by ID

        Args:
            table_id: Table ID

        Returns:
            Table object if found, None otherwise
        """
        query = """
            SELECT id, name, description, schema_definition, created_by, created_at, updated_at, is_active
            FROM tables
            WHERE id = ? AND is_active = TRUE
            LIMIT 1
        """

        result = self.execute(query, (table_id,))

        if not result:
            return None

        row = result[0]
        return Table(
            id=row['id'],
            name=row['name'],
            description=row['description'],
            schema_definition=row['schema_definition'],
            created_by=row['created_by'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            is_active=row['is_active']
        )

    def get_table_by_name(self, name: str) -> Optional[Table]:
        """
        Get table by name (case-insensitive)

        Args:
            name: Table name

        Returns:
            Table object if found, None otherwise
        """
        query = """
            SELECT id, name, description, schema_definition, created_by, created_at, updated_at, is_active
            FROM tables
            WHERE LOWER(name) = LOWER(?) AND is_active = TRUE
            LIMIT 1
        """

        result = self.execute(query, (name,))

        if not result:
            return None

        row = result[0]
        return Table(
            id=row['id'],
            name=row['name'],
            description=row['description'],
            schema_definition=row['schema_definition'],
            created_by=row['created_by'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            is_active=row['is_active']
        )

    def get_all_tables(self, skip: int = 0, limit: int = 100) -> List[Table]:
        """
        Get all active tables with pagination

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of Table objects
        """
        query = """
            SELECT id, name, description, schema_definition, created_by, created_at, updated_at, is_active
            FROM tables
            WHERE is_active = TRUE
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        """

        result = self.execute(query, (limit, skip))

        tables = []
        for row in result:
            tables.append(Table(
                id=row['id'],
                name=row['name'],
                description=row['description'],
                schema_definition=row['schema_definition'],
                created_by=row['created_by'],
                created_at=row['created_at'],
                updated_at=row['updated_at'],
                is_active=row['is_active']
            ))

        return tables

    def update_table_metadata(
        self,
        table_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        schema_definition: Optional[str] = None
    ) -> Optional[Table]:
        """
        Update table metadata

        Args:
            table_id: Table ID
            name: Optional new table name
            description: Optional new description
            schema_definition: Optional new schema definition (JSON string)

        Returns:
            Updated Table object if found, None otherwise
        """
        # Build dynamic UPDATE query with only provided fields.
        # Pass updated_at as a bound parameter to avoid the DuckDB bug where
        # CURRENT_TIMESTAMP in a SET clause re-evaluates sequence DEFAULTs.
        from datetime import datetime, timezone
        set_clauses = ["updated_at = ?"]
        params = [datetime.now(timezone.utc)]

        if name is not None:
            set_clauses.append("name = ?")
            params.append(name)

        if description is not None:
            set_clauses.append("description = ?")
            params.append(description)

        if schema_definition is not None:
            set_clauses.append("schema_definition = ?")
            params.append(schema_definition)

        # Add table_id parameter
        params.append(table_id)

        # Construct the query
        update_query = f"""
            UPDATE tables
            SET {', '.join(set_clauses)}
            WHERE id = ? AND is_active = TRUE
        """

        conn = self.get_connection()
        conn.execute(update_query, tuple(params))

        # Fetch the updated record
        return self.get_table_by_id(table_id)

    def soft_delete_table(self, table_id: int) -> bool:
        """
        Soft delete table (set is_active = FALSE)

        Args:
            table_id: Table ID

        Returns:
            True if table was deleted, False if not found
        """
        query = """
            UPDATE tables
            SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND is_active = TRUE
        """

        conn = self.get_connection()
        result = conn.execute(query, (table_id,))

        # Check if any rows were affected
        return result.fetchone() is not None if result else False

    # -------------------------------------------------------------------------
    # Table data methods (physical row storage)
    # -------------------------------------------------------------------------

    def ensure_physical_table(self, table: Table) -> None:
        """
        Create the physical DuckDB table for storing user data if it doesn't exist.
        The table name is prefixed with 'data_' and uses the metadata table's id
        to avoid naming collisions with system tables.
        """
        import json
        schema = json.loads(table.schema_definition)
        columns = schema.get("columns", [])

        col_defs = ["_row_id INTEGER PRIMARY KEY DEFAULT nextval('seq_data_{id}_id')".format(id=table.id)]
        for col in columns:
            col_type = col["type"].upper()
            nullable = "" if col.get("nullable", True) else " NOT NULL"
            col_defs.append(f'"{col["name"]}" {col_type}{nullable}')

        conn = self.get_connection()
        conn.execute(f"CREATE SEQUENCE IF NOT EXISTS seq_data_{table.id}_id START 1")
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS data_{table.id} ({', '.join(col_defs)})"
        )

    def insert_rows(self, table: Table, rows: list) -> int:
        """
        Insert one or more rows into the physical data table.

        Returns:
            Number of rows inserted
        """
        if not rows:
            return 0

        self.ensure_physical_table(table)
        conn = self.get_connection()
        columns = list(rows[0].keys())
        col_list = ", ".join(f'"{c}"' for c in columns)
        placeholders = ", ".join("?" for _ in columns)

        for row in rows:
            values = tuple(row[c] for c in columns)
            conn.execute(
                f"INSERT INTO data_{table.id} ({col_list}) VALUES ({placeholders})",
                values
            )

        return len(rows)

    def query_rows(self, table: Table, filters: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Query rows from the physical data table, optionally applying filters.
        Each filter is a dict: {"column": str, "op": str, "value": any}
        Supported ops: eq, ne, gt, gte, lt, lte
        """
        self.ensure_physical_table(table)
        conn = self.get_connection()

        op_map = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}

        where_clauses = []
        params = []
        if filters:
            for f in filters:
                col = f["column"]
                op = op_map.get(f["op"], "=")
                where_clauses.append(f'"{col}" {op} ?')
                params.append(f["value"])

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        query = f"SELECT * FROM data_{table.id} {where_sql} ORDER BY _row_id"

        result = conn.execute(query, tuple(params)) if params else conn.execute(query)
        columns = [desc[0] for desc in result.description] if result.description else []
        rows = result.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    def update_row(self, table: Table, row_id: int, updates: Dict[str, Any]) -> bool:
        """
        Update a single row in the physical data table.

        Returns:
            True if the row was updated, raises NotFoundException if not found.
        """
        import json
        schema = json.loads(table.schema_definition)
        allowed_columns = {col["name"] for col in schema.get("columns", [])}
        unknown = set(updates.keys()) - allowed_columns
        if unknown:
            raise ValidationException(
                f"Unknown columns: {', '.join(sorted(unknown))}. "
                f"Allowed: {', '.join(sorted(allowed_columns))}"
            )

        self.ensure_physical_table(table)
        conn = self.get_connection()

        set_parts = [f'"{col}" = ?' for col in updates.keys()]
        params = list(updates.values()) + [row_id]
        conn.execute(
            f"UPDATE data_{table.id} SET {', '.join(set_parts)} WHERE _row_id = ?",
            params
        )

        check = conn.execute(
            f"SELECT _row_id FROM data_{table.id} WHERE _row_id = ?", [row_id]
        ).fetchone()
        if check is None:
            raise NotFoundException(f"Row {row_id} not found")

        return True

    def delete_row(self, table: Table, row_id: int) -> bool:
        """
        Delete a single row from the physical data table.

        Returns:
            True if the row was deleted, raises NotFoundException if not found.
        """
        self.ensure_physical_table(table)
        conn = self.get_connection()

        check = conn.execute(
            f"SELECT _row_id FROM data_{table.id} WHERE _row_id = ?", [row_id]
        ).fetchone()
        if check is None:
            raise NotFoundException(f"Row {row_id} not found")

        conn.execute(f"DELETE FROM data_{table.id} WHERE _row_id = ?", [row_id])
        return True

    # -------------------------------------------------------------------------
    # Execution history methods
    # -------------------------------------------------------------------------

    def save_execution(self, result, executed_by: int) -> Execution:
        """
        Persist an ExecutionResult to the executions table.
        Step output (row data) is intentionally excluded to keep the DB lean.

        Returns:
            Execution record with the new id
        """
        import json
        steps_summary = [
            {
                "step_id": s.step_id,
                "step_name": s.step_name,
                "step_type": s.step_type,
                "success": s.success,
                "rows_out": s.rows_out,
                "error": s.error,
            }
            for s in result.steps
        ]
        final_output_count = len(result.final_output) if result.final_output else 0

        query = """
            INSERT INTO executions (
                workflow_id, workflow_name, success, executed_at, executed_by,
                error, step_count, steps_json, final_output_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            RETURNING id, workflow_id, workflow_name, success, executed_at,
                      executed_by, error, step_count, steps_json,
                      final_output_count, created_at
        """
        rows = self.execute(query, (
            result.workflow_id,
            result.workflow_name,
            result.success,
            result.executed_at,
            executed_by,
            result.error,
            len(result.steps),
            json.dumps(steps_summary),
            final_output_count,
        ))
        return Execution(**rows[0])

    def get_executions_for_workflow(
        self, workflow_id: int, skip: int = 0, limit: int = 50
    ) -> List[Execution]:
        """
        Return past executions for a workflow, newest first.
        """
        query = """
            SELECT id, workflow_id, workflow_name, success, executed_at,
                   executed_by, error, step_count, steps_json,
                   final_output_count, created_at
            FROM executions
            WHERE workflow_id = ?
            ORDER BY executed_at DESC
            LIMIT ? OFFSET ?
        """
        rows = self.execute(query, (workflow_id, limit, skip))
        return [Execution(**row) for row in rows] if rows else []

    def get_workflow_analytics(self, workflow_id: int) -> Optional[Dict[str, Any]]:
        """
        Return aggregated execution stats for a workflow.
        Returns None if the workflow does not exist.
        """
        workflow = self.get_workflow_by_id(workflow_id)
        if not workflow:
            return None

        row = self.execute("""
            SELECT
                COUNT(*)                                            AS total_runs,
                SUM(CASE WHEN success THEN 1 ELSE 0 END)           AS successful_runs,
                SUM(CASE WHEN NOT success THEN 1 ELSE 0 END)       AS failed_runs,
                AVG(step_count)                                     AS avg_steps_per_run,
                AVG(CASE WHEN success THEN final_output_count END)  AS avg_output_rows,
                MIN(executed_at)                                    AS first_run_at,
                MAX(executed_at)                                    AS last_run_at,
                SUM(CASE WHEN executed_at >= CAST(CURRENT_TIMESTAMP AS TIMESTAMP) - INTERVAL 7 DAYS  THEN 1 ELSE 0 END) AS runs_last_7_days,
                SUM(CASE WHEN executed_at >= CAST(CURRENT_TIMESTAMP AS TIMESTAMP) - INTERVAL 30 DAYS THEN 1 ELSE 0 END) AS runs_last_30_days
            FROM executions
            WHERE workflow_id = ?
        """, (workflow_id,))[0]

        total = row["total_runs"] or 0
        successful = row["successful_runs"] or 0

        return {
            "workflow_id": workflow_id,
            "workflow_name": workflow.name,
            "total_runs": total,
            "successful_runs": successful,
            "failed_runs": row["failed_runs"] or 0,
            "success_rate": round(successful / total, 4) if total > 0 else 0.0,
            "avg_steps_per_run": round(float(row["avg_steps_per_run"] or 0), 2),
            "avg_output_rows": round(float(row["avg_output_rows"] or 0), 2),
            "first_run_at": row["first_run_at"],
            "last_run_at": row["last_run_at"],
            "runs_last_7_days": row["runs_last_7_days"] or 0,
            "runs_last_30_days": row["runs_last_30_days"] or 0,
        }

    # -------------------------------------------------------------------------
    # Workflow methods
    # -------------------------------------------------------------------------

    def create_workflow(self, name: str, description: Optional[str], status: str, created_by: int) -> Workflow:
        """Create a new workflow record."""
        query = """
            INSERT INTO workflows (name, description, status, created_by, created_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
            RETURNING id, name, description, status, created_by, created_at, updated_at, is_active
        """
        result = self.execute(query, (name, description, status, created_by))
        if not result:
            raise Exception("Failed to create workflow")
        row = result[0]
        return Workflow(**row)

    def get_workflow_by_id(self, workflow_id: int) -> Optional[Workflow]:
        """Get a workflow by ID."""
        query = """
            SELECT id, name, description, status, created_by, created_at, updated_at, is_active
            FROM workflows WHERE id = ? AND is_active = TRUE LIMIT 1
        """
        result = self.execute(query, (workflow_id,))
        if not result:
            return None
        return Workflow(**result[0])

    def get_all_workflows(self, skip: int = 0, limit: int = 100) -> List[Workflow]:
        """Get all active workflows with pagination."""
        query = """
            SELECT id, name, description, status, created_by, created_at, updated_at, is_active
            FROM workflows WHERE is_active = TRUE
            ORDER BY created_at DESC LIMIT ? OFFSET ?
        """
        result = self.execute(query, (limit, skip))
        return [Workflow(**row) for row in result]

    def update_workflow(
        self,
        workflow_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None
    ) -> Optional[Workflow]:
        """Update workflow fields. Only provided fields are changed.
        updated_at is passed as a bound parameter (not a SQL expression) to
        avoid the DuckDB bug where CURRENT_TIMESTAMP in a SET clause causes
        the sequence DEFAULT to be re-evaluated, triggering a PK violation.
        """
        from datetime import datetime, timezone
        set_clauses = ["updated_at = ?"]
        params = [datetime.now(timezone.utc)]
        if name is not None:
            set_clauses.append("name = ?")
            params.append(name)
        if description is not None:
            set_clauses.append("description = ?")
            params.append(description)
        if status is not None:
            set_clauses.append("status = ?")
            params.append(status)
        params.append(workflow_id)
        conn = self.get_connection()
        conn.execute(
            f"UPDATE workflows SET {', '.join(set_clauses)} WHERE id = ? AND is_active = TRUE",
            tuple(params)
        )
        return self.get_workflow_by_id(workflow_id)

    def soft_delete_workflow(self, workflow_id: int) -> bool:
        """Soft delete a workflow."""
        from datetime import datetime, timezone
        conn = self.get_connection()
        conn.execute(
            "UPDATE workflows SET is_active = FALSE, updated_at = ? WHERE id = ? AND is_active = TRUE",
            (datetime.now(timezone.utc), workflow_id)
        )
        return self.get_workflow_by_id(workflow_id) is None

    # -------------------------------------------------------------------------
    # Step methods
    # -------------------------------------------------------------------------

    def create_step(self, workflow_id: int, name: str, step_type: str, config: str, order: int) -> Step:
        """Create a new step for a workflow."""
        query = """
            INSERT INTO steps (workflow_id, name, step_type, config, "order", created_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
            RETURNING id, workflow_id, name, step_type, config, "order", created_at, updated_at, is_active
        """
        result = self.execute(query, (workflow_id, name, step_type, config, order))
        if not result:
            raise Exception("Failed to create step")
        row = result[0]
        return Step(
            id=row["id"],
            workflow_id=row["workflow_id"],
            name=row["name"],
            step_type=row["step_type"],
            config=row["config"],
            order=row["order"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            is_active=row["is_active"]
        )

    def get_steps_by_workflow(self, workflow_id: int) -> List[Step]:
        """Get all active steps for a workflow, ordered by execution order."""
        query = """
            SELECT id, workflow_id, name, step_type, config, "order", created_at, updated_at, is_active
            FROM steps WHERE workflow_id = ? AND is_active = TRUE ORDER BY "order" ASC
        """
        result = self.execute(query, (workflow_id,))
        return [
            Step(
                id=row["id"],
                workflow_id=row["workflow_id"],
                name=row["name"],
                step_type=row["step_type"],
                config=row["config"],
                order=row["order"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                is_active=row["is_active"]
            )
            for row in result
        ]

    def get_step_by_id(self, step_id: int) -> Optional[Step]:
        """Get a step by ID."""
        query = """
            SELECT id, workflow_id, name, step_type, config, "order", created_at, updated_at, is_active
            FROM steps WHERE id = ? AND is_active = TRUE LIMIT 1
        """
        result = self.execute(query, (step_id,))
        if not result:
            return None
        row = result[0]
        return Step(
            id=row["id"],
            workflow_id=row["workflow_id"],
            name=row["name"],
            step_type=row["step_type"],
            config=row["config"],
            order=row["order"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            is_active=row["is_active"]
        )

    # ------------------------------------------------------------------
    # Schedule methods
    # ------------------------------------------------------------------

    def _row_to_schedule(self, row: Dict[str, Any]) -> Schedule:
        return Schedule(
            id=row["id"],
            workflow_id=row["workflow_id"],
            cron_expr=row["cron_expr"],
            is_enabled=row["is_enabled"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_run_at=row["last_run_at"],
            next_run_at=row["next_run_at"],
        )

    def create_schedule(
        self,
        workflow_id: int,
        cron_expr: str,
        is_enabled: bool,
        created_by: int,
        next_run_at=None,
    ) -> Schedule:
        """Insert a new schedule row. One schedule per workflow (UNIQUE on workflow_id)."""
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        query = """
            INSERT INTO schedules
                (workflow_id, cron_expr, is_enabled, created_by, created_at, updated_at, next_run_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING id, workflow_id, cron_expr, is_enabled, created_by,
                      created_at, updated_at, last_run_at, next_run_at
        """
        result = self.execute(query, (workflow_id, cron_expr, is_enabled, created_by, now, now, next_run_at))
        return self._row_to_schedule(result[0])

    def get_schedule_by_workflow(self, workflow_id: int) -> Optional[Schedule]:
        """Return the schedule for a workflow, or None."""
        result = self.execute(
            "SELECT * FROM schedules WHERE workflow_id = ? LIMIT 1",
            (workflow_id,)
        )
        return self._row_to_schedule(result[0]) if result else None

    def get_all_enabled_schedules(self) -> List[Schedule]:
        """Return all enabled schedules (used at startup to register jobs)."""
        result = self.execute("SELECT * FROM schedules WHERE is_enabled = TRUE")
        return [self._row_to_schedule(r) for r in result]

    def update_schedule(
        self,
        workflow_id: int,
        cron_expr: Optional[str] = None,
        is_enabled: Optional[bool] = None,
        next_run_at=None,
    ) -> Optional[Schedule]:
        """Partially update a schedule row. Returns None if not found."""
        from datetime import datetime, timezone
        existing = self.get_schedule_by_workflow(workflow_id)
        if not existing:
            return None

        new_cron = cron_expr if cron_expr is not None else existing.cron_expr
        new_enabled = is_enabled if is_enabled is not None else existing.is_enabled
        new_next = next_run_at if next_run_at is not None else existing.next_run_at
        now = datetime.now(timezone.utc)

        self.execute(
            """
            UPDATE schedules
            SET cron_expr = ?, is_enabled = ?, next_run_at = ?, updated_at = ?
            WHERE workflow_id = ?
            """,
            (new_cron, new_enabled, new_next, now, workflow_id)
        )
        return self.get_schedule_by_workflow(workflow_id)

    def update_schedule_last_run(self, workflow_id: int, last_run_at, next_run_at) -> None:
        """Stamp last_run_at and next_run_at after a scheduled execution."""
        from datetime import datetime, timezone
        self.execute(
            "UPDATE schedules SET last_run_at = ?, next_run_at = ?, updated_at = ? WHERE workflow_id = ?",
            (last_run_at, next_run_at, datetime.now(timezone.utc), workflow_id)
        )

    def delete_schedule(self, workflow_id: int) -> bool:
        """Delete a schedule row. Returns True if a row was deleted."""
        existing = self.get_schedule_by_workflow(workflow_id)
        if not existing:
            return False
        self.execute("DELETE FROM schedules WHERE workflow_id = ?", (workflow_id,))
        return True

    # Workflow template methods

    def _row_to_template(self, row: Dict[str, Any]) -> WorkflowTemplate:
        return WorkflowTemplate(
            id=row["id"],
            name=row["name"],
            description=row.get("description"),
            tags=row["tags"],
            step_configs=row["step_configs"],
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            is_active=row["is_active"],
        )

    def create_template(
        self,
        name: str,
        description: Optional[str],
        tags: str,
        step_configs: str,
        created_by: int,
    ) -> WorkflowTemplate:
        result = self.execute(
            """
            INSERT INTO workflow_templates
                (name, description, tags, step_configs, created_by, created_at, updated_at, is_active)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, TRUE)
            RETURNING id, name, description, tags, step_configs, created_by, created_at, updated_at, is_active
            """,
            (name, description, tags, step_configs, created_by),
        )
        if not result:
            raise Exception("Failed to create workflow template")
        return self._row_to_template(result[0])

    def get_template_by_id(self, template_id: int) -> Optional[WorkflowTemplate]:
        result = self.execute(
            """
            SELECT id, name, description, tags, step_configs, created_by, created_at, updated_at, is_active
            FROM workflow_templates
            WHERE id = ? AND is_active = TRUE
            LIMIT 1
            """,
            (template_id,),
        )
        return self._row_to_template(result[0]) if result else None

    def get_all_templates(self, skip: int = 0, limit: int = 100) -> List[WorkflowTemplate]:
        result = self.execute(
            """
            SELECT id, name, description, tags, step_configs, created_by, created_at, updated_at, is_active
            FROM workflow_templates
            WHERE is_active = TRUE
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, skip),
        )
        return [self._row_to_template(r) for r in result]

    def soft_delete_template(self, template_id: int) -> None:
        from datetime import datetime, timezone
        self.execute(
            "UPDATE workflow_templates SET is_active = FALSE, updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc), template_id),
        )
