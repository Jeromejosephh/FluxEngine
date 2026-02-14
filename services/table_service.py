"""Table management service"""
import json
import re
from typing import Optional, List, Dict, Any

from schemas.table import TableCreate, TableUpdate
from models.table import Table
from services.duckdb_service import DuckDBService
from utils.exceptions import ValidationException, NotFoundException, DatabaseException


class TableService:
    """Service for table management operations"""

    # Supported DuckDB column types
    SUPPORTED_TYPES = {
        'INTEGER', 'VARCHAR', 'BOOLEAN', 'TIMESTAMP', 'FLOAT', 'DATE'
    }

    # Reserved system table names
    RESERVED_NAMES = {
        'users', 'workflows', 'steps', 'tables', 'audit_entries'
    }

    def __init__(self):
        self.db_service = DuckDBService()

    def validate_schema(self, schema_definition: Dict[str, Any]) -> None:
        """
        Validate table schema definition

        Args:
            schema_definition: Schema dictionary with column definitions

        Raises:
            ValidationException: If schema is invalid
        """
        # Check if 'columns' key exists
        if "columns" not in schema_definition:
            raise ValidationException("Schema must contain 'columns' key")

        columns = schema_definition.get("columns", [])

        # Check if columns is a list and not empty
        if not isinstance(columns, list) or not columns:
            raise ValidationException("Schema must have at least one column")

        # Track column names for uniqueness check
        column_names = set()

        # Validate each column
        for i, column in enumerate(columns):
            if not isinstance(column, dict):
                raise ValidationException(f"Column at index {i} must be a dictionary")

            # Check required fields
            if "name" not in column:
                raise ValidationException(f"Column at index {i} missing 'name' field")

            if "type" not in column:
                raise ValidationException(f"Column at index {i} missing 'type' field")

            col_name = column["name"]
            col_type = column["type"]

            # Validate column name type
            if not isinstance(col_name, str) or not col_name:
                raise ValidationException(f"Column name at index {i} must be a non-empty string")

            # Validate column name pattern (alphanumeric + underscore, must start with letter or underscore)
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', col_name):
                raise ValidationException(
                    f"Column name '{col_name}' must start with letter or underscore "
                    f"and contain only letters, numbers, and underscores"
                )

            # Check for duplicate column names (case-insensitive)
            col_name_lower = col_name.lower()
            if col_name_lower in column_names:
                raise ValidationException(f"Duplicate column name: '{col_name}'")
            column_names.add(col_name_lower)

            # Validate column type
            if not isinstance(col_type, str):
                raise ValidationException(f"Column type for '{col_name}' must be a string")

            col_type_upper = col_type.upper()
            if col_type_upper not in self.SUPPORTED_TYPES:
                raise ValidationException(
                    f"Unsupported column type '{col_type}' for column '{col_name}'. "
                    f"Supported types: {', '.join(sorted(self.SUPPORTED_TYPES))}"
                )

            # Validate optional fields if present
            if "nullable" in column and not isinstance(column["nullable"], bool):
                raise ValidationException(f"Column '{col_name}' nullable field must be boolean")

            if "primary_key" in column and not isinstance(column["primary_key"], bool):
                raise ValidationException(f"Column '{col_name}' primary_key field must be boolean")

    def validate_table_name(self, name: str, exclude_id: Optional[int] = None) -> None:
        """
        Validate table name

        Args:
            name: Table name to validate
            exclude_id: Optional table ID to exclude from uniqueness check (for updates)

        Raises:
            ValidationException: If name is invalid or already exists
        """
        # Check if name is reserved
        if name.lower() in self.RESERVED_NAMES:
            raise ValidationException(
                f"Table name '{name}' is reserved. "
                f"Reserved names: {', '.join(sorted(self.RESERVED_NAMES))}"
            )

        # Validate name pattern (alphanumeric + underscore, must start with letter or underscore)
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
            raise ValidationException(
                f"Table name '{name}' must start with letter or underscore "
                f"and contain only letters, numbers, and underscores"
            )

        # Check for duplicate table name (case-insensitive)
        existing_table = self.db_service.get_table_by_name(name)
        if existing_table:
            # If exclude_id is provided and matches, skip uniqueness check (update scenario)
            if exclude_id is None or existing_table.id != exclude_id:
                raise ValidationException(f"Table with name '{name}' already exists")

    def create_table(self, table_data: TableCreate, user_id: int) -> Table:
        """
        Create a new table

        Args:
            table_data: Table creation data
            user_id: ID of user creating the table

        Returns:
            Created Table object

        Raises:
            ValidationException: If validation fails
            DatabaseException: If database operation fails
        """
        # Validate table name
        self.validate_table_name(table_data.name)

        # Validate schema definition
        self.validate_schema(table_data.schema_definition)

        # Convert schema_definition dict to JSON string
        schema_json = json.dumps(table_data.schema_definition)

        # Create table metadata in database
        try:
            table = self.db_service.create_table_metadata(
                name=table_data.name,
                description=table_data.description,
                schema_definition=schema_json,
                created_by=user_id
            )
            return table

        except Exception as e:
            # Check if it's a unique constraint violation
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                raise ValidationException(f"Table with name '{table_data.name}' already exists")
            raise DatabaseException(f"Failed to create table: {str(e)}")

    def get_table_by_id(self, table_id: int) -> Table:
        """
        Get table by ID

        Args:
            table_id: Table ID

        Returns:
            Table object

        Raises:
            NotFoundException: If table not found
        """
        table = self.db_service.get_table_by_id(table_id)

        if not table:
            raise NotFoundException(f"Table with ID {table_id} not found")

        return table

    def get_all_tables(self, skip: int = 0, limit: int = 100) -> List[Table]:
        """
        Get all tables with pagination

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of Table objects
        """
        return self.db_service.get_all_tables(skip=skip, limit=limit)

    def update_table(self, table_id: int, updates: TableUpdate, user_id: int) -> Table:
        """
        Update table metadata

        Args:
            table_id: Table ID
            updates: Table update data
            user_id: ID of user updating the table

        Returns:
            Updated Table object

        Raises:
            NotFoundException: If table not found
            ValidationException: If validation fails
        """
        # Verify table exists
        existing_table = self.get_table_by_id(table_id)

        # Validate name if provided
        if updates.name is not None:
            self.validate_table_name(updates.name, exclude_id=table_id)

        # Validate schema if provided
        if updates.schema_definition is not None:
            self.validate_schema(updates.schema_definition)

        # Convert schema_definition to JSON string if provided
        schema_json = None
        if updates.schema_definition is not None:
            schema_json = json.dumps(updates.schema_definition)

        # Update table metadata
        try:
            table = self.db_service.update_table_metadata(
                table_id=table_id,
                name=updates.name,
                description=updates.description,
                schema_definition=schema_json
            )

            if not table:
                raise NotFoundException(f"Table with ID {table_id} not found")

            return table

        except ValidationException:
            raise
        except NotFoundException:
            raise
        except Exception as e:
            # Check if it's a unique constraint violation
            if "unique" in str(e).lower() or "duplicate" in str(e).lower():
                raise ValidationException(f"Table with name '{updates.name}' already exists")
            raise DatabaseException(f"Failed to update table: {str(e)}")

    def delete_table(self, table_id: int, user_id: int) -> None:
        """
        Soft delete a table

        Args:
            table_id: Table ID
            user_id: ID of user deleting the table (for audit)

        Raises:
            NotFoundException: If table not found
        """
        # Verify table exists before attempting deletion
        self.get_table_by_id(table_id)

        # Soft delete the table
        success = self.db_service.soft_delete_table(table_id)

        if not success:
            raise NotFoundException(f"Table with ID {table_id} not found")
