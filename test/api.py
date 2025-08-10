"""
API layer - handles HTTP requests and responses
"""
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import json
import logging
from dataclasses import asdict

# Import from our business layer
from .models import User, Product, UserService, ProductService, validate_business_rules
from .database import ConnectionPool, create_database_connection, DatabaseError


class APIError(Exception):
    """Custom exception for API errors"""
    
    def __init__(self, message: str, status_code: int = 400, error_code: str = None):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code or "GENERIC_ERROR"
        super().__init__(self.message)


class ValidationError(APIError):
    """Exception for validation errors"""
    
    def __init__(self, errors: List[str]):
        self.errors = errors
        message = f"Validation failed: {', '.join(errors)}"
        super().__init__(message, status_code=400, error_code="VALIDATION_ERROR")


class NotFoundError(APIError):
    """Exception for not found errors"""
    
    def __init__(self, resource: str, identifier: Union[int, str]):
        message = f"{resource} with identifier '{identifier}' not found"
        super().__init__(message, status_code=404, error_code="NOT_FOUND")


class AuthenticationError(APIError):
    """Exception for authentication errors"""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, status_code=401, error_code="AUTH_ERROR")


class AuthorizationError(APIError):
    """Exception for authorization errors"""
    
    def __init__(self, message: str = "Access denied"):
        super().__init__(message, status_code=403, error_code="ACCESS_DENIED")


class APIResponse:
    """Standardized API response format"""
    
    def __init__(self, data: Any = None, message: str = None, 
                 status_code: int = 200, errors: List[str] = None):
        self.data = data
        self.message = message or "Success"
        self.status_code = status_code
        self.errors = errors or []
        self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary"""
        response = {
            'status': 'success' if self.status_code < 400 else 'error',
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'status_code': self.status_code
        }
        
        if self.data is not None:
            response['data'] = self._serialize_data(self.data)
        
        if self.errors:
            response['errors'] = self.errors
        
        return response
    
    def _serialize_data(self, data: Any) -> Any:
        """Serialize data for JSON response"""
        if isinstance(data, (User, Product)):
            return data.to_dict()
        elif isinstance(data, list):
            return [self._serialize_data(item) for item in data]
        elif isinstance(data, dict):
            return {key: self._serialize_data(value) for key, value in data.items()}
        elif hasattr(data, 'to_dict'):
            return data.to_dict()
        else:
            return data
    
    def to_json(self) -> str:
        """Convert response to JSON string"""
        return json.dumps(self.to_dict(), indent=2)


class RequestValidator:
    """Validates incoming API requests"""
    
    @staticmethod
    def validate_user_creation_request(data: Dict[str, Any]) -> List[str]:
        """Validate user creation request data"""
        errors = []
        
        required_fields = ['username', 'email', 'password', 'first_name', 'last_name']
        for field in required_fields:
            if not data.get(field):
                errors.append(f"{field} is required")
        
        # Additional validation using business rules
        business_errors = validate_business_rules('user', data)
        errors.extend(business_errors)
        
        # Password strength validation
        password = data.get('password', '')
        if password and len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        return errors
    
    @staticmethod
    def validate_product_creation_request(data: Dict[str, Any]) -> List[str]:
        """Validate product creation request data"""
        errors = []
        
        required_fields = ['name', 'description', 'price', 'category']
        for field in required_fields:
            if not data.get(field):
                errors.append(f"{field} is required")
        
        # Additional validation using business rules
        business_errors = validate_business_rules('product', data)
        errors.extend(business_errors)
        
        # Price validation
        price = data.get('price')
        if price is not None:
            try:
                price = float(price)
                if price < 0:
                    errors.append("Price cannot be negative")
            except (ValueError, TypeError):
                errors.append("Price must be a valid number")
        
        # Stock quantity validation
        stock_quantity = data.get('stock_quantity')
        if stock_quantity is not None:
            try:
                stock_quantity = int(stock_quantity)
                if stock_quantity < 0:
                    errors.append("Stock quantity cannot be negative")
            except (ValueError, TypeError):
                errors.append("Stock quantity must be a valid integer")
        
        return errors
    
    @staticmethod
    def validate_pagination_params(params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize pagination parameters"""
        try:
            limit = int(params.get('limit', 20))
            offset = int(params.get('offset', 0))
            
            # Apply reasonable limits
            limit = max(1, min(limit, 100))  # Between 1 and 100
            offset = max(0, offset)  # Non-negative
            
            return {'limit': limit, 'offset': offset}
        except (ValueError, TypeError):
            raise ValidationError(["Invalid pagination parameters"])


class UserController:
    """Controller for user-related API endpoints"""
    
    def __init__(self, connection_pool: ConnectionPool):
        self.user_service = UserService(connection_pool)
        self.logger = logging.getLogger(__name__)
    
    def create_user(self, request_data: Dict[str, Any]) -> APIResponse:
        """Create a new user"""
        try:
            # Validate request
            errors = RequestValidator.validate_user_creation_request(request_data)
            if errors:
                raise ValidationError(errors)
            
            # Create user
            user = self.user_service.create_user(
                username=request_data['username'],
                email=request_data['email'],
                password=request_data['password'],
                first_name=request_data['first_name'],
                last_name=request_data['last_name']
            )
            
            self.logger.info(f"Created user: {user.username}")
            return APIResponse(
                data=user,
                message="User created successfully",
                status_code=201
            )
            
        except ValidationError:
            raise
        except ValueError as e:
            raise ValidationError([str(e)])
        except Exception as e:
            self.logger.error(f"Error creating user: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def get_user(self, user_id: int) -> APIResponse:
        """Get a user by ID"""
        try:
            user = self.user_service.user_repository.find_by_id(user_id)
            if not user:
                raise NotFoundError("User", user_id)
            
            return APIResponse(data=user)
            
        except NotFoundError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting user {user_id}: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def update_user(self, user_id: int, request_data: Dict[str, Any]) -> APIResponse:
        """Update a user"""
        try:
            # Validate that user exists
            existing_user = self.user_service.user_repository.find_by_id(user_id)
            if not existing_user:
                raise NotFoundError("User", user_id)
            
            # Update user
            updated_user = self.user_service.update_user_profile(user_id, request_data)
            
            self.logger.info(f"Updated user: {updated_user.username}")
            return APIResponse(
                data=updated_user,
                message="User updated successfully"
            )
            
        except (NotFoundError, ValueError):
            raise
        except Exception as e:
            self.logger.error(f"Error updating user {user_id}: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def authenticate_user(self, request_data: Dict[str, Any]) -> APIResponse:
        """Authenticate a user"""
        try:
            username = request_data.get('username')
            password = request_data.get('password')
            
            if not username or not password:
                raise ValidationError(["Username and password are required"])
            
            user = self.user_service.authenticate_user(username, password)
            if not user:
                raise AuthenticationError("Invalid username or password")
            
            # Generate session token (simplified)
            session_token = self._generate_session_token(user)
            
            response_data = {
                'user': user,
                'session_token': session_token,
                'expires_at': (datetime.now() + timedelta(hours=24)).isoformat()
            }
            
            return APIResponse(
                data=response_data,
                message="Authentication successful"
            )
            
        except (ValidationError, AuthenticationError):
            raise
        except Exception as e:
            self.logger.error(f"Error authenticating user: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def get_users_by_role(self, role: str, pagination_params: Dict[str, Any]) -> APIResponse:
        """Get users by role with pagination"""
        try:
            # Validate pagination
            params = RequestValidator.validate_pagination_params(pagination_params)
            
            # Get users
            users = self.user_service.get_users_by_role(role)
            
            # Apply pagination (simplified - normally done in database)
            start = params['offset']
            end = start + params['limit']
            paginated_users = users[start:end]
            
            response_data = {
                'users': paginated_users,
                'pagination': {
                    'total': len(users),
                    'limit': params['limit'],
                    'offset': params['offset'],
                    'has_next': end < len(users)
                }
            }
            
            return APIResponse(data=response_data)
            
        except ValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting users by role {role}: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def _generate_session_token(self, user: User) -> str:
        """Generate a session token for the user"""
        import hashlib
        token_data = f"{user.id}_{user.username}_{datetime.now().timestamp()}"
        return hashlib.sha256(token_data.encode()).hexdigest()


class ProductController:
    """Controller for product-related API endpoints"""
    
    def __init__(self, connection_pool: ConnectionPool):
        self.product_service = ProductService(connection_pool)
        self.logger = logging.getLogger(__name__)
    
    def create_product(self, request_data: Dict[str, Any]) -> APIResponse:
        """Create a new product"""
        try:
            # Validate request
            errors = RequestValidator.validate_product_creation_request(request_data)
            if errors:
                raise ValidationError(errors)
            
            # Create product
            product = self.product_service.create_product(
                name=request_data['name'],
                description=request_data['description'],
                price=float(request_data['price']),
                category=request_data['category'],
                stock_quantity=int(request_data.get('stock_quantity', 0))
            )
            
            self.logger.info(f"Created product: {product.name}")
            return APIResponse(
                data=product,
                message="Product created successfully",
                status_code=201
            )
            
        except ValidationError:
            raise
        except ValueError as e:
            raise ValidationError([str(e)])
        except Exception as e:
            self.logger.error(f"Error creating product: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def get_product(self, product_id: int) -> APIResponse:
        """Get a product by ID"""
        try:
            product = self.product_service.product_repository.find_by_id(product_id)
            if not product:
                raise NotFoundError("Product", product_id)
            
            return APIResponse(data=product)
            
        except NotFoundError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting product {product_id}: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def update_product_stock(self, product_id: int, request_data: Dict[str, Any]) -> APIResponse:
        """Update product stock"""
        try:
            quantity_change = request_data.get('quantity_change')
            if quantity_change is None:
                raise ValidationError(["quantity_change is required"])
            
            try:
                quantity_change = int(quantity_change)
            except (ValueError, TypeError):
                raise ValidationError(["quantity_change must be an integer"])
            
            # Update stock
            product = self.product_service.update_product_stock(product_id, quantity_change)
            
            self.logger.info(f"Updated stock for product {product_id}: {quantity_change}")
            return APIResponse(
                data=product,
                message="Product stock updated successfully"
            )
            
        except (ValidationError, ValueError):
            raise
        except Exception as e:
            self.logger.error(f"Error updating product stock {product_id}: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def search_products(self, request_params: Dict[str, Any]) -> APIResponse:
        """Search products"""
        try:
            search_term = request_params.get('q', '').strip()
            if not search_term:
                raise ValidationError(["Search term 'q' is required"])
            
            # Validate pagination
            pagination_params = RequestValidator.validate_pagination_params(request_params)
            
            # Search products
            products = self.product_service.search_products(search_term)
            
            # Apply pagination (simplified - normally done in database)
            start = pagination_params['offset']
            end = start + pagination_params['limit']
            paginated_products = products[start:end]
            
            response_data = {
                'products': paginated_products,
                'search_term': search_term,
                'pagination': {
                    'total': len(products),
                    'limit': pagination_params['limit'],
                    'offset': pagination_params['offset'],
                    'has_next': end < len(products)
                }
            }
            
            return APIResponse(data=response_data)
            
        except ValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Error searching products: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def get_products_by_category(self, category: str, pagination_params: Dict[str, Any]) -> APIResponse:
        """Get products by category"""
        try:
            # Validate pagination
            params = RequestValidator.validate_pagination_params(pagination_params)
            
            # Get products
            products = self.product_service.get_products_by_category(category)
            
            # Apply pagination (simplified - normally done in database)
            start = params['offset']
            end = start + params['limit']
            paginated_products = products[start:end]
            
            response_data = {
                'products': paginated_products,
                'category': category,
                'pagination': {
                    'total': len(products),
                    'limit': params['limit'],
                    'offset': params['offset'],
                    'has_next': end < len(products)
                }
            }
            
            return APIResponse(data=response_data)
            
        except ValidationError:
            raise
        except Exception as e:
            self.logger.error(f"Error getting products by category {category}: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def get_low_stock_products(self, request_params: Dict[str, Any]) -> APIResponse:
        """Get products with low stock"""
        try:
            threshold = int(request_params.get('threshold', 10))
            pagination_params = RequestValidator.validate_pagination_params(request_params)
            
            # Get low stock products
            products = self.product_service.get_low_stock_products(threshold)
            
            # Apply pagination
            start = pagination_params['offset']
            end = start + pagination_params['limit']
            paginated_products = products[start:end]
            
            response_data = {
                'products': paginated_products,
                'threshold': threshold,
                'pagination': {
                    'total': len(products),
                    'limit': pagination_params['limit'],
                    'offset': pagination_params['offset'],
                    'has_next': end < len(products)
                }
            }
            
            return APIResponse(data=response_data)
            
        except (ValueError, ValidationError):
            raise ValidationError(["Invalid threshold parameter"])
        except Exception as e:
            self.logger.error(f"Error getting low stock products: {str(e)}")
            raise APIError("Internal server error", status_code=500)


class APIApplication:
    """Main API application class"""
    
    def __init__(self):
        self.connection_pool = create_database_connection()
        self.user_controller = UserController(self.connection_pool)
        self.product_controller = ProductController(self.connection_pool)
        self.logger = logging.getLogger(__name__)
        
        # Setup logging
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    def handle_request(self, method: str, endpoint: str, data: Dict[str, Any] = None, 
                      params: Dict[str, Any] = None) -> APIResponse:
        """Handle incoming API requests"""
        try:
            self.logger.info(f"Handling {method} request to {endpoint}")
            
            # Route the request
            if endpoint.startswith('/users'):
                return self._route_user_request(method, endpoint, data, params)
            elif endpoint.startswith('/products'):
                return self._route_product_request(method, endpoint, data, params)
            else:
                raise APIError("Endpoint not found", status_code=404)
                
        except APIError:
            raise
        except Exception as e:
            self.logger.error(f"Unhandled error: {str(e)}")
            raise APIError("Internal server error", status_code=500)
    
    def _route_user_request(self, method: str, endpoint: str, 
                           data: Dict[str, Any], params: Dict[str, Any]) -> APIResponse:
        """Route user-related requests"""
        if method == 'POST' and endpoint == '/users':
            return self.user_controller.create_user(data or {})
        elif method == 'POST' and endpoint == '/users/auth':
            return self.user_controller.authenticate_user(data or {})
        elif method == 'GET' and endpoint.startswith('/users/'):
            user_id = self._extract_id_from_endpoint(endpoint, '/users/')
            return self.user_controller.get_user(user_id)
        elif method == 'PUT' and endpoint.startswith('/users/'):
            user_id = self._extract_id_from_endpoint(endpoint, '/users/')
            return self.user_controller.update_user(user_id, data or {})
        elif method == 'GET' and endpoint.startswith('/users/role/'):
            role = endpoint.split('/users/role/')[-1]
            return self.user_controller.get_users_by_role(role, params or {})
        else:
            raise APIError("Endpoint not found", status_code=404)
    
    def _route_product_request(self, method: str, endpoint: str, 
                              data: Dict[str, Any], params: Dict[str, Any]) -> APIResponse:
        """Route product-related requests"""
        if method == 'POST' and endpoint == '/products':
            return self.product_controller.create_product(data or {})
        elif method == 'GET' and endpoint.startswith('/products/'):
            if '/stock' in endpoint:
                # Handle stock update
                product_id = self._extract_id_from_endpoint(endpoint, '/products/', '/stock')
                return self.product_controller.update_product_stock(product_id, data or {})
            else:
                product_id = self._extract_id_from_endpoint(endpoint, '/products/')
                return self.product_controller.get_product(product_id)
        elif method == 'GET' and endpoint == '/products/search':
            return self.product_controller.search_products(params or {})
        elif method == 'GET' and endpoint.startswith('/products/category/'):
            category = endpoint.split('/products/category/')[-1]
            return self.product_controller.get_products_by_category(category, params or {})
        elif method == 'GET' and endpoint == '/products/low-stock':
            return self.product_controller.get_low_stock_products(params or {})
        else:
            raise APIError("Endpoint not found", status_code=404)
    
    def _extract_id_from_endpoint(self, endpoint: str, prefix: str, suffix: str = '') -> int:
        """Extract ID from endpoint path"""
        try:
            path_part = endpoint.replace(prefix, '').replace(suffix, '')
            return int(path_part.split('/')[0])
        except (ValueError, IndexError):
            raise APIError("Invalid endpoint format", status_code=400)
    
    def shutdown(self):
        """Shutdown the application"""
        self.logger.info("Shutting down API application")
        # Clean up connections
        if hasattr(self.connection_pool, 'cleanup_stale_connections'):
            self.connection_pool.cleanup_stale_connections(timeout_minutes=0)


def create_api_application() -> APIApplication:
    """Factory function to create API application"""
    return APIApplication()


def format_error_response(error: APIError) -> Dict[str, Any]:
    """Format error as API response"""
    response = APIResponse(
        message=error.message,
        status_code=error.status_code,
        errors=[error.message] if hasattr(error, 'errors') and error.errors else None
    )
    return response.to_dict()


def log_request_response(method: str, endpoint: str, request_data: Dict[str, Any], 
                        response: APIResponse) -> None:
    """Log request and response for debugging"""
    logger = logging.getLogger(__name__)
    logger.info(f"Request: {method} {endpoint}")
    logger.info(f"Request Data: {json.dumps(request_data, indent=2)}")
    logger.info(f"Response: {response.status_code} - {response.message}")
    if response.errors:
        logger.warning(f"Response Errors: {response.errors}")
