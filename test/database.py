"""
Database layer - handles data persistence and retrieval
"""
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta


class DatabaseError(Exception):
    """Custom exception for database operations"""
    pass


class ConnectionPool:
    """Manages database connections"""
    
    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self.active_connections = []
        self.available_connections = []
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize the connection pool"""
        for i in range(self.max_connections):
            connection = self._create_connection()
            self.available_connections.append(connection)
    
    def _create_connection(self):
        """Create a new database connection"""
        return {
            'id': len(self.active_connections) + len(self.available_connections),
            'created_at': datetime.now(),
            'last_used': None
        }
    
    def get_connection(self):
        """Get an available connection from the pool"""
        if not self.available_connections:
            raise DatabaseError("No available connections in pool")
        
        connection = self.available_connections.pop()
        connection['last_used'] = datetime.now()
        self.active_connections.append(connection)
        return connection
    
    def return_connection(self, connection):
        """Return a connection to the pool"""
        if connection in self.active_connections:
            self.active_connections.remove(connection)
            self.available_connections.append(connection)
    
    def cleanup_stale_connections(self, timeout_minutes: int = 30):
        """Clean up connections that haven't been used recently"""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        
        stale_connections = []
        for conn in self.active_connections:
            if conn['last_used'] and conn['last_used'] < cutoff_time:
                stale_connections.append(conn)
        
        for conn in stale_connections:
            self.return_connection(conn)
        
        return len(stale_connections)


class BaseRepository:
    """Base repository class with common database operations"""
    
    def __init__(self, connection_pool: ConnectionPool):
        self.connection_pool = connection_pool
        self.table_name = None
    
    def _get_connection(self):
        """Get a database connection"""
        return self.connection_pool.get_connection()
    
    def _return_connection(self, connection):
        """Return a database connection to the pool"""
        self.connection_pool.return_connection(connection)
    
    def _execute_query(self, query: str, params: Optional[Dict] = None):
        """Execute a database query"""
        connection = self._get_connection()
        try:
            # Simulate query execution
            result = self._simulate_query_execution(query, params)
            return result
        finally:
            self._return_connection(connection)
    
    def _simulate_query_execution(self, query: str, params: Optional[Dict] = None):
        """Simulate query execution for testing"""
        # This would normally execute against a real database
        return {
            'query': query,
            'params': params or {},
            'executed_at': datetime.now(),
            'rows_affected': 1
        }
    
    def find_by_id(self, entity_id: int):
        """Find an entity by its ID"""
        query = f"SELECT * FROM {self.table_name} WHERE id = :id"
        params = {'id': entity_id}
        
        result = self._execute_query(query, params)
        return self._map_result_to_entity(result)
    
    def find_all(self, limit: int = 100, offset: int = 0):
        """Find all entities with pagination"""
        query = f"SELECT * FROM {self.table_name} LIMIT :limit OFFSET :offset"
        params = {'limit': limit, 'offset': offset}
        
        result = self._execute_query(query, params)
        return [self._map_result_to_entity(row) for row in result.get('rows', [])]
    
    def save(self, entity: Dict[str, Any]):
        """Save an entity to the database"""
        if 'id' in entity:
            return self._update_entity(entity)
        else:
            return self._create_entity(entity)
    
    def _create_entity(self, entity: Dict[str, Any]):
        """Create a new entity"""
        columns = ', '.join(entity.keys())
        placeholders = ', '.join([f':{key}' for key in entity.keys()])
        
        query = f"INSERT INTO {self.table_name} ({columns}) VALUES ({placeholders})"
        result = self._execute_query(query, entity)
        
        # Simulate returning the created entity with an ID
        entity['id'] = self._generate_new_id()
        entity['created_at'] = datetime.now()
        return entity
    
    def _update_entity(self, entity: Dict[str, Any]):
        """Update an existing entity"""
        set_clause = ', '.join([f"{key} = :{key}" for key in entity.keys() if key != 'id'])
        query = f"UPDATE {self.table_name} SET {set_clause} WHERE id = :id"
        
        result = self._execute_query(query, entity)
        entity['updated_at'] = datetime.now()
        return entity
    
    def delete(self, entity_id: int):
        """Delete an entity by ID"""
        query = f"DELETE FROM {self.table_name} WHERE id = :id"
        params = {'id': entity_id}
        
        result = self._execute_query(query, params)
        return result['rows_affected'] > 0
    
    def _map_result_to_entity(self, result):
        """Map database result to entity object"""
        # Simulate mapping database row to entity
        return {
            'id': result.get('id', 1),
            'created_at': datetime.now(),
            'updated_at': None
        }
    
    def _generate_new_id(self):
        """Generate a new ID for entities"""
        return hash(str(datetime.now())) % 10000


class TransactionManager:
    """Manages database transactions"""
    
    def __init__(self, connection_pool: ConnectionPool):
        self.connection_pool = connection_pool
        self.active_transactions = {}
    
    def begin_transaction(self, transaction_id: str):
        """Begin a new transaction"""
        if transaction_id in self.active_transactions:
            raise DatabaseError(f"Transaction {transaction_id} is already active")
        
        connection = self.connection_pool.get_connection()
        self.active_transactions[transaction_id] = {
            'connection': connection,
            'started_at': datetime.now(),
            'operations': []
        }
        
        return transaction_id
    
    def add_operation(self, transaction_id: str, operation: Dict[str, Any]):
        """Add an operation to a transaction"""
        if transaction_id not in self.active_transactions:
            raise DatabaseError(f"Transaction {transaction_id} not found")
        
        transaction = self.active_transactions[transaction_id]
        transaction['operations'].append({
            'operation': operation,
            'timestamp': datetime.now()
        })
    
    def commit_transaction(self, transaction_id: str):
        """Commit a transaction"""
        if transaction_id not in self.active_transactions:
            raise DatabaseError(f"Transaction {transaction_id} not found")
        
        transaction = self.active_transactions[transaction_id]
        
        try:
            # Simulate committing all operations
            for op in transaction['operations']:
                self._execute_operation(op['operation'])
            
            # Return connection to pool
            self.connection_pool.return_connection(transaction['connection'])
            del self.active_transactions[transaction_id]
            
            return True
        except Exception as e:
            self.rollback_transaction(transaction_id)
            raise DatabaseError(f"Failed to commit transaction: {str(e)}")
    
    def rollback_transaction(self, transaction_id: str):
        """Rollback a transaction"""
        if transaction_id not in self.active_transactions:
            raise DatabaseError(f"Transaction {transaction_id} not found")
        
        transaction = self.active_transactions[transaction_id]
        
        # Return connection to pool
        self.connection_pool.return_connection(transaction['connection'])
        del self.active_transactions[transaction_id]
        
        return True
    
    def _execute_operation(self, operation: Dict[str, Any]):
        """Execute a single operation"""
        # Simulate operation execution
        return {
            'success': True,
            'operation': operation,
            'executed_at': datetime.now()
        }
    
    def get_active_transaction_count(self):
        """Get the number of active transactions"""
        return len(self.active_transactions)
    
    def cleanup_stale_transactions(self, timeout_minutes: int = 60):
        """Clean up transactions that have been running too long"""
        cutoff_time = datetime.now() - timedelta(minutes=timeout_minutes)
        stale_transactions = []
        
        for tx_id, tx_data in self.active_transactions.items():
            if tx_data['started_at'] < cutoff_time:
                stale_transactions.append(tx_id)
        
        for tx_id in stale_transactions:
            self.rollback_transaction(tx_id)
        
        return len(stale_transactions)


def create_database_connection():
    """Factory function to create database connections"""
    return ConnectionPool(max_connections=20)


def validate_query_params(params: Dict[str, Any]) -> bool:
    """Validate query parameters"""
    if not isinstance(params, dict):
        return False
    
    # Check for SQL injection patterns
    dangerous_patterns = ['DROP', 'DELETE', 'INSERT', 'UPDATE']
    for key, value in params.items():
        if isinstance(value, str):
            for pattern in dangerous_patterns:
                if pattern.lower() in value.lower():
                    return False
    
    return True


def sanitize_table_name(table_name: str) -> str:
    """Sanitize table names to prevent SQL injection"""
    if not isinstance(table_name, str):
        raise ValueError("Table name must be a string")
    
    # Remove potentially dangerous characters
    allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_')
    sanitized = ''.join(c for c in table_name if c in allowed_chars)
    
    if not sanitized:
        raise ValueError("Invalid table name")
    
    return sanitized
