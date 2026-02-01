"""Audit logging service"""
from typing import Optional
from datetime import datetime

from services.duckdb_service import DuckDBService


class AuditService:
    """Service for audit logging"""
    
    def __init__(self):
        self.db_service = DuckDBService()
    
    def log_action(
        self,
        action: str,
        entity_type: str,
        user_id: Optional[int] = None,
        entity_id: Optional[int] = None,
        details: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> None:
        """
        Log an audit entry
        
        Args:
            action: Action performed (e.g., 'create', 'update', 'delete', 'login')
            entity_type: Type of entity affected (e.g., 'user', 'table', 'workflow')
            user_id: Optional ID of user performing the action
            entity_id: Optional ID of entity affected
            details: Optional additional details (JSON string)
            ip_address: Optional IP address of request
        """
        query = """
            INSERT INTO audit_entries (
                user_id, action, entity_type, entity_id, details, ip_address, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """
        
        params = (
            user_id,
            action,
            entity_type,
            entity_id,
            details,
            ip_address,
            datetime.utcnow()
        )
        
        try:
            self.db_service.execute(query, params)
        except Exception as e:
            # Log error but don't fail the operation
            # TODO: Add proper logging
            print(f"Failed to log audit entry: {e}")
    
    def get_user_audit_log(self, user_id: int, limit: int = 100) -> list:
        """
        Get audit log entries for a specific user
        
        Args:
            user_id: User ID
            limit: Maximum number of entries to return
            
        Returns:
            List of audit entries
        """
        query = """
            SELECT * FROM audit_entries
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """
        
        return self.db_service.execute(query, (user_id, limit))
    
    def get_entity_audit_log(
        self,
        entity_type: str,
        entity_id: int,
        limit: int = 100
    ) -> list:
        """
        Get audit log entries for a specific entity
        
        Args:
            entity_type: Type of entity
            entity_id: Entity ID
            limit: Maximum number of entries to return
            
        Returns:
            List of audit entries
        """
        query = """
            SELECT * FROM audit_entries
            WHERE entity_type = ? AND entity_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """
        
        return self.db_service.execute(query, (entity_type, entity_id, limit))
