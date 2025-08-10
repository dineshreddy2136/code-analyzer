"""
Utility functions and helpers used across the application
"""
import hashlib
import re
import json
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass

# Import from other modules
from .database import ConnectionPool, DatabaseError, validate_query_params, sanitize_table_name
from .models import User, Product, hash_user_password
from .api import APIError, ValidationError, format_error_response


class ConfigurationError(Exception):
    """Exception for configuration-related errors"""
    pass


@dataclass
class ApplicationConfig:
    """Application configuration settings"""
    database_max_connections: int = 20
    api_rate_limit: int = 100  # requests per minute
    session_timeout_hours: int = 24
    password_min_length: int = 8
    log_level: str = "INFO"
    debug_mode: bool = False
    allowed_file_extensions: List[str] = None
    max_file_size_mb: int = 10
    
    def __post_init__(self):
        if self.allowed_file_extensions is None:
            self.allowed_file_extensions = ['.jpg', '.jpeg', '.png', '.pdf', '.txt']
    
    def validate(self) -> List[str]:
        """Validate configuration settings"""
        errors = []
        
        if self.database_max_connections <= 0:
            errors.append("database_max_connections must be positive")
        
        if self.api_rate_limit <= 0:
            errors.append("api_rate_limit must be positive")
        
        if self.session_timeout_hours <= 0:
            errors.append("session_timeout_hours must be positive")
        
        if self.password_min_length < 6:
            errors.append("password_min_length must be at least 6")
        
        if self.log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            errors.append("log_level must be a valid logging level")
        
        if self.max_file_size_mb <= 0:
            errors.append("max_file_size_mb must be positive")
        
        return errors


class SecurityUtils:
    """Security-related utility functions"""
    
    @staticmethod
    def hash_password_secure(password: str, salt: str = None) -> tuple[str, str]:
        """Hash password with salt using secure method"""
        if not salt:
            salt = SecurityUtils.generate_salt()
        
        # Use PBKDF2 for better security (simplified version)
        iterations = 100000
        hash_value = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
        return hash_value.hex(), salt
    
    @staticmethod
    def verify_password_secure(password: str, hash_value: str, salt: str) -> bool:
        """Verify password against secure hash"""
        computed_hash, _ = SecurityUtils.hash_password_secure(password, salt)
        return computed_hash == hash_value
    
    @staticmethod
    def generate_salt() -> str:
        """Generate random salt for password hashing"""
        import os
        return os.urandom(32).hex()
    
    @staticmethod
    def generate_api_key() -> str:
        """Generate a secure API key"""
        import os
        return hashlib.sha256(os.urandom(64)).hexdigest()
    
    @staticmethod
    def sanitize_input(input_string: str, max_length: int = 255) -> str:
        """Sanitize user input to prevent XSS and other attacks"""
        if not isinstance(input_string, str):
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\']', '', input_string)
        
        # Limit length
        sanitized = sanitized[:max_length]
        
        # Strip whitespace
        return sanitized.strip()
    
    @staticmethod
    def validate_email_format(email: str) -> bool:
        """Validate email format using regex"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_phone_format(phone: str) -> bool:
        """Validate phone number format"""
        # Remove all non-digits
        digits_only = re.sub(r'\D', '', phone)
        
        # Check if it's a valid length (10-15 digits)
        return 10 <= len(digits_only) <= 15
    
    @staticmethod
    def is_safe_filename(filename: str) -> bool:
        """Check if filename is safe (no path traversal)"""
        if not filename:
            return False
        
        # Check for path traversal attempts
        dangerous_patterns = ['..', '/', '\\', '~']
        for pattern in dangerous_patterns:
            if pattern in filename:
                return False
        
        return True


class CacheManager:
    """Simple in-memory cache manager"""
    
    def __init__(self, default_ttl: int = 3600):  # 1 hour default
        self.cache = {}
        self.ttl_data = {}
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key not in self.cache:
            return None
        
        # Check if expired
        if self._is_expired(key):
            self.delete(key)
            return None
        
        return self.cache[key]
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL"""
        self.cache[key] = value
        
        expiry_time = datetime.now() + timedelta(seconds=ttl or self.default_ttl)
        self.ttl_data[key] = expiry_time
    
    def delete(self, key: str) -> None:
        """Delete value from cache"""
        self.cache.pop(key, None)
        self.ttl_data.pop(key, None)
    
    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
        self.ttl_data.clear()
    
    def _is_expired(self, key: str) -> bool:
        """Check if cache entry is expired"""
        if key not in self.ttl_data:
            return True
        
        return datetime.now() > self.ttl_data[key]
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count"""
        expired_keys = []
        
        for key in list(self.cache.keys()):
            if self._is_expired(key):
                expired_keys.append(key)
        
        for key in expired_keys:
            self.delete(key)
        
        return len(expired_keys)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_entries = len(self.cache)
        expired_count = sum(1 for key in self.cache.keys() if self._is_expired(key))
        
        return {
            'total_entries': total_entries,
            'active_entries': total_entries - expired_count,
            'expired_entries': expired_count
        }


class DataExporter:
    """Export data to various formats"""
    
    @staticmethod
    def export_users_to_json(users: List[User], include_sensitive: bool = False) -> str:
        """Export users to JSON format"""
        user_data = []
        
        for user in users:
            user_dict = user.to_dict()
            
            # Remove sensitive data if requested
            if not include_sensitive:
                user_dict.pop('password_hash', None)
                user_dict.pop('profile_data', None)
            
            user_data.append(user_dict)
        
        return json.dumps(user_data, indent=2, default=str)
    
    @staticmethod
    def export_products_to_json(products: List[Product]) -> str:
        """Export products to JSON format"""
        product_data = [product.to_dict() for product in products]
        return json.dumps(product_data, indent=2, default=str)
    
    @staticmethod
    def export_to_csv(data: List[Dict[str, Any]], columns: List[str]) -> str:
        """Export data to CSV format"""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        
        for row in data:
            # Only include specified columns
            filtered_row = {col: row.get(col, '') for col in columns}
            writer.writerow(filtered_row)
        
        return output.getvalue()
    
    @staticmethod
    def create_backup_data(connection_pool: ConnectionPool) -> Dict[str, Any]:
        """Create backup data from database"""
        from .models import UserRepository, ProductRepository
        
        user_repo = UserRepository(connection_pool)
        product_repo = ProductRepository(connection_pool)
        
        # Get all data (in real app, this might be paginated)
        users = user_repo.find_all(limit=1000)
        products = product_repo.find_all(limit=1000)
        
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0',
            'users': DataExporter.export_users_to_json(users, include_sensitive=True),
            'products': DataExporter.export_products_to_json(products),
            'stats': {
                'total_users': len(users),
                'total_products': len(products)
            }
        }
        
        return backup_data


class MetricsCollector:
    """Collect application metrics"""
    
    def __init__(self):
        self.metrics = {
            'requests_total': 0,
            'requests_by_endpoint': {},
            'errors_total': 0,
            'errors_by_type': {},
            'response_times': [],
            'active_users': 0,
            'database_queries': 0
        }
    
    def record_request(self, endpoint: str, response_time: float) -> None:
        """Record API request metrics"""
        self.metrics['requests_total'] += 1
        self.metrics['requests_by_endpoint'][endpoint] = \
            self.metrics['requests_by_endpoint'].get(endpoint, 0) + 1
        self.metrics['response_times'].append(response_time)
        
        # Keep only last 1000 response times
        if len(self.metrics['response_times']) > 1000:
            self.metrics['response_times'] = self.metrics['response_times'][-1000:]
    
    def record_error(self, error_type: str) -> None:
        """Record error metrics"""
        self.metrics['errors_total'] += 1
        self.metrics['errors_by_type'][error_type] = \
            self.metrics['errors_by_type'].get(error_type, 0) + 1
    
    def record_database_query(self) -> None:
        """Record database query metrics"""
        self.metrics['database_queries'] += 1
    
    def update_active_users(self, count: int) -> None:
        """Update active users count"""
        self.metrics['active_users'] = count
    
    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        response_times = self.metrics['response_times']
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            'total_requests': self.metrics['requests_total'],
            'total_errors': self.metrics['errors_total'],
            'error_rate': (self.metrics['errors_total'] / max(self.metrics['requests_total'], 1)) * 100,
            'average_response_time': round(avg_response_time, 3),
            'active_users': self.metrics['active_users'],
            'database_queries': self.metrics['database_queries'],
            'top_endpoints': sorted(
                self.metrics['requests_by_endpoint'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            'top_errors': sorted(
                self.metrics['errors_by_type'].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }
    
    def reset(self) -> None:
        """Reset all metrics"""
        self.__init__()


class TaskScheduler:
    """Simple task scheduler for background jobs"""
    
    def __init__(self):
        self.scheduled_tasks = []
        self.running_tasks = {}
    
    def schedule_recurring_task(self, task_name: str, task_func, interval_minutes: int) -> None:
        """Schedule a recurring task"""
        task_info = {
            'name': task_name,
            'function': task_func,
            'interval': timedelta(minutes=interval_minutes),
            'next_run': datetime.now() + timedelta(minutes=interval_minutes),
            'last_run': None,
            'run_count': 0
        }
        
        self.scheduled_tasks.append(task_info)
    
    def schedule_one_time_task(self, task_name: str, task_func, run_at: datetime) -> None:
        """Schedule a one-time task"""
        task_info = {
            'name': task_name,
            'function': task_func,
            'next_run': run_at,
            'last_run': None,
            'run_count': 0,
            'one_time': True
        }
        
        self.scheduled_tasks.append(task_info)
    
    def run_pending_tasks(self) -> List[str]:
        """Run any pending tasks"""
        now = datetime.now()
        completed_tasks = []
        
        for task in self.scheduled_tasks[:]:  # Copy list to allow modification
            if task['next_run'] <= now:
                try:
                    # Run the task
                    task['function']()
                    task['last_run'] = now
                    task['run_count'] += 1
                    completed_tasks.append(task['name'])
                    
                    # Schedule next run if recurring
                    if not task.get('one_time', False):
                        task['next_run'] = now + task['interval']
                    else:
                        # Remove one-time tasks after completion
                        self.scheduled_tasks.remove(task)
                
                except Exception as e:
                    logging.error(f"Task '{task['name']}' failed: {str(e)}")
        
        return completed_tasks
    
    def get_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """Get list of scheduled tasks"""
        return [{
            'name': task['name'],
            'next_run': task['next_run'].isoformat(),
            'last_run': task['last_run'].isoformat() if task['last_run'] else None,
            'run_count': task['run_count'],
            'one_time': task.get('one_time', False)
        } for task in self.scheduled_tasks]


def setup_application_logging(config: ApplicationConfig) -> None:
    """Setup application-wide logging"""
    level = getattr(logging, config.log_level.upper())
    
    format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    if config.debug_mode:
        format_string = '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    
    logging.basicConfig(
        level=level,
        format=format_string,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler('application.log')
        ]
    )


def create_sample_data(connection_pool: ConnectionPool) -> Dict[str, Any]:
    """Create sample data for testing"""
    from .models import UserService, ProductService
    
    user_service = UserService(connection_pool)
    product_service = ProductService(connection_pool)
    
    # Create sample users
    sample_users = []
    for i in range(5):
        user = user_service.create_user(
            username=f"user{i+1}",
            email=f"user{i+1}@example.com",
            password="SecurePass123",
            first_name=f"User{i+1}",
            last_name="TestUser"
        )
        sample_users.append(user)
    
    # Create sample products
    categories = ['Electronics', 'Books', 'Clothing', 'Home', 'Sports']
    sample_products = []
    
    for i in range(10):
        product = product_service.create_product(
            name=f"Product {i+1}",
            description=f"Description for product {i+1}",
            price=round(10.0 + (i * 5.0), 2),
            category=categories[i % len(categories)],
            stock_quantity=100 + (i * 10)
        )
        sample_products.append(product)
    
    return {
        'users_created': len(sample_users),
        'products_created': len(sample_products),
        'sample_users': sample_users,
        'sample_products': sample_products
    }


def perform_health_check(connection_pool: ConnectionPool) -> Dict[str, Any]:
    """Perform application health check"""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'checks': {}
    }
    
    # Check database connection
    try:
        connection = connection_pool.get_connection()
        connection_pool.return_connection(connection)
        health_status['checks']['database'] = 'healthy'
    except Exception as e:
        health_status['checks']['database'] = f'unhealthy: {str(e)}'
        health_status['status'] = 'unhealthy'
    
    # Check memory usage (simplified)
    try:
        import psutil
        memory_percent = psutil.virtual_memory().percent
        health_status['checks']['memory'] = f'{memory_percent}% used'
        if memory_percent > 90:
            health_status['status'] = 'warning'
    except ImportError:
        health_status['checks']['memory'] = 'monitoring unavailable'
    
    return health_status


def cleanup_application_resources(connection_pool: ConnectionPool, 
                                cache_manager: CacheManager,
                                metrics_collector: MetricsCollector) -> Dict[str, Any]:
    """Cleanup application resources"""
    cleanup_results = {}
    
    # Cleanup database connections
    try:
        stale_connections = connection_pool.cleanup_stale_connections(timeout_minutes=30)
        cleanup_results['database'] = f'Cleaned up {stale_connections} stale connections'
    except Exception as e:
        cleanup_results['database'] = f'Error cleaning database: {str(e)}'
    
    # Cleanup cache
    try:
        expired_entries = cache_manager.cleanup_expired()
        cleanup_results['cache'] = f'Removed {expired_entries} expired cache entries'
    except Exception as e:
        cleanup_results['cache'] = f'Error cleaning cache: {str(e)}'
    
    # Get final metrics before potential reset
    try:
        final_metrics = metrics_collector.get_summary()
        cleanup_results['metrics'] = f'Final metrics collected: {final_metrics["total_requests"]} requests processed'
    except Exception as e:
        cleanup_results['metrics'] = f'Error collecting metrics: {str(e)}'
    
    return cleanup_results

def generate_secure_token(length=32):
    import secrets
    import base64
    token_bytes = secrets.randbytes(length)
    return base64.b64encode(token_bytes).decode('utf-8')

