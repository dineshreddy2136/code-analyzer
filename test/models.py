"""
Business logic layer - contains domain models and business rules
"""
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
import hashlib
import json

# Import from our database layer
from .database import BaseRepository, ConnectionPool, TransactionManager, DatabaseError


@dataclass
class User:
    """User domain model"""
    username: str
    email: str
    password_hash: str
    first_name: str
    last_name: str
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    is_active: bool = True
    roles: List[str] = field(default_factory=list)
    profile_data: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now()
    
    def get_full_name(self) -> str:
        """Get the user's full name"""
        return f"{self.first_name} {self.last_name}".strip()
    
    def has_role(self, role: str) -> bool:
        """Check if user has a specific role"""
        return role in self.roles
    
    def add_role(self, role: str) -> None:
        """Add a role to the user"""
        if role not in self.roles:
            self.roles.append(role)
    
    def remove_role(self, role: str) -> None:
        """Remove a role from the user"""
        if role in self.roles:
            self.roles.remove(role)
    
    def is_admin(self) -> bool:
        """Check if user is an administrator"""
        return self.has_role('admin')
    
    def update_last_login(self) -> None:
        """Update the last login timestamp"""
        self.last_login = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_active': self.is_active,
            'roles': self.roles,
            'profile_data': self.profile_data
        }


@dataclass
class Product:
    """Product domain model"""
    name: str
    description: str
    price: float
    category: str
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    sku: Optional[str] = None
    stock_quantity: int = 0
    is_available: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now()
        if not self.sku:
            self.sku = self._generate_sku()
    
    def _generate_sku(self) -> str:
        """Generate a unique SKU for the product"""
        base_string = f"{self.name}_{self.category}_{datetime.now().timestamp()}"
        return hashlib.md5(base_string.encode()).hexdigest()[:12].upper()
    
    def is_in_stock(self) -> bool:
        """Check if product is in stock"""
        return self.stock_quantity > 0 and self.is_available
    
    def update_stock(self, quantity: int) -> None:
        """Update stock quantity"""
        self.stock_quantity = max(0, self.stock_quantity + quantity)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the product"""
        if tag not in self.tags:
            self.tags.append(tag)
    
    def remove_tag(self, tag: str) -> None:
        """Remove a tag from the product"""
        if tag in self.tags:
            self.tags.remove(tag)
    
    def calculate_discounted_price(self, discount_percentage: float) -> float:
        """Calculate discounted price"""
        if not (0 <= discount_percentage <= 100):
            raise ValueError("Discount percentage must be between 0 and 100")
        
        discount_amount = self.price * (discount_percentage / 100)
        return round(self.price - discount_amount, 2)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert product to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'category': self.category,
            'sku': self.sku,
            'stock_quantity': self.stock_quantity,
            'is_available': self.is_available,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'tags': self.tags,
            'metadata': self.metadata
        }


class UserService:
    """Service class for user business logic"""
    
    def __init__(self, connection_pool: ConnectionPool):
        self.user_repository = UserRepository(connection_pool)
        self.transaction_manager = TransactionManager(connection_pool)
    
    def create_user(self, username: str, email: str, password: str, 
                   first_name: str, last_name: str) -> User:
        """Create a new user"""
        # Validate inputs
        if not self._validate_username(username):
            raise ValueError("Invalid username")
        
        if not self._validate_email(email):
            raise ValueError("Invalid email")
        
        if not self._validate_password(password):
            raise ValueError("Password does not meet requirements")
        
        # Check if user already exists
        if self.user_repository.find_by_username(username):
            raise ValueError("Username already exists")
        
        if self.user_repository.find_by_email(email):
            raise ValueError("Email already exists")
        
        # Create user with hashed password
        password_hash = self._hash_password(password)
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            first_name=first_name,
            last_name=last_name
        )
        
        return self.user_repository.save(user)
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user"""
        user = self.user_repository.find_by_username(username)
        if not user:
            return None
        
        if not user.is_active:
            return None
        
        if not self._verify_password(password, user.password_hash):
            return None
        
        user.update_last_login()
        self.user_repository.save(user)
        
        return user
    
    def update_user_profile(self, user_id: int, profile_data: Dict[str, Any]) -> User:
        """Update user profile data"""
        user = self.user_repository.find_by_id(user_id)
        if not user:
            raise ValueError("User not found")
        
        # Validate profile data
        allowed_fields = ['first_name', 'last_name', 'profile_data']
        for key in profile_data.keys():
            if key not in allowed_fields:
                raise ValueError(f"Field '{key}' cannot be updated")
        
        # Update user fields
        for key, value in profile_data.items():
            if key == 'profile_data':
                user.profile_data.update(value)
            else:
                setattr(user, key, value)
        
        user.updated_at = datetime.now()
        return self.user_repository.save(user)
    
    def deactivate_user(self, user_id: int) -> bool:
        """Deactivate a user account"""
        user = self.user_repository.find_by_id(user_id)
        if not user:
            return False
        
        user.is_active = False
        user.updated_at = datetime.now()
        self.user_repository.save(user)
        
        return True
    
    def get_users_by_role(self, role: str) -> List[User]:
        """Get all users with a specific role"""
        return self.user_repository.find_by_role(role)
    
    def _validate_username(self, username: str) -> bool:
        """Validate username format"""
        if not isinstance(username, str):
            return False
        if len(username) < 3 or len(username) > 50:
            return False
        if not username.isalnum():
            return False
        return True
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        if not isinstance(email, str):
            return False
        if '@' not in email:
            return False
        if len(email) > 254:
            return False
        return True
    
    def _validate_password(self, password: str) -> bool:
        """Validate password strength"""
        if not isinstance(password, str):
            return False
        if len(password) < 8:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        return True
    
    def _hash_password(self, password: str) -> str:
        """Hash a password"""
        salt = "django_salt"  # In real app, use random salt
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify a password against its hash"""
        return self._hash_password(password) == password_hash


class ProductService:
    """Service class for product business logic"""
    
    def __init__(self, connection_pool: ConnectionPool):
        self.product_repository = ProductRepository(connection_pool)
        self.transaction_manager = TransactionManager(connection_pool)
    
    def create_product(self, name: str, description: str, price: float, 
                      category: str, stock_quantity: int = 0) -> Product:
        """Create a new product"""
        # Validate inputs
        if not name or len(name.strip()) == 0:
            raise ValueError("Product name is required")
        
        if price < 0:
            raise ValueError("Price cannot be negative")
        
        if stock_quantity < 0:
            raise ValueError("Stock quantity cannot be negative")
        
        product = Product(
            name=name.strip(),
            description=description.strip(),
            price=round(price, 2),
            category=category.strip(),
            stock_quantity=stock_quantity
        )
        
        return self.product_repository.save(product)
    
    def update_product_stock(self, product_id: int, quantity_change: int) -> Product:
        """Update product stock quantity"""
        product = self.product_repository.find_by_id(product_id)
        if not product:
            raise ValueError("Product not found")
        
        tx_id = f"stock_update_{product_id}_{datetime.now().timestamp()}"
        
        try:
            self.transaction_manager.begin_transaction(tx_id)
            
            # Update stock
            old_stock = product.stock_quantity
            product.update_stock(quantity_change)
            
            # Log the operation
            operation = {
                'type': 'stock_update',
                'product_id': product_id,
                'old_stock': old_stock,
                'new_stock': product.stock_quantity,
                'change': quantity_change
            }
            self.transaction_manager.add_operation(tx_id, operation)
            
            # Save product
            updated_product = self.product_repository.save(product)
            
            self.transaction_manager.commit_transaction(tx_id)
            return updated_product
            
        except Exception as e:
            self.transaction_manager.rollback_transaction(tx_id)
            raise
    
    def get_products_by_category(self, category: str) -> List[Product]:
        """Get all products in a category"""
        return self.product_repository.find_by_category(category)
    
    def search_products(self, search_term: str) -> List[Product]:
        """Search products by name or description"""
        return self.product_repository.search(search_term)
    
    def get_low_stock_products(self, threshold: int = 10) -> List[Product]:
        """Get products with low stock"""
        return self.product_repository.find_low_stock(threshold)


class UserRepository(BaseRepository):
    """Repository for user data access"""
    
    def __init__(self, connection_pool: ConnectionPool):
        super().__init__(connection_pool)
        self.table_name = "users"
    
    def find_by_username(self, username: str) -> Optional[User]:
        """Find user by username"""
        query = f"SELECT * FROM {self.table_name} WHERE username = :username"
        params = {'username': username}
        
        result = self._execute_query(query, params)
        if result.get('rows'):
            return self._map_result_to_user(result['rows'][0])
        return None
    
    def find_by_email(self, email: str) -> Optional[User]:
        """Find user by email"""
        query = f"SELECT * FROM {self.table_name} WHERE email = :email"
        params = {'email': email}
        
        result = self._execute_query(query, params)
        if result.get('rows'):
            return self._map_result_to_user(result['rows'][0])
        return None
    
    def find_by_role(self, role: str) -> List[User]:
        """Find users by role"""
        query = f"SELECT * FROM {self.table_name} WHERE roles LIKE :role"
        params = {'role': f'%{role}%'}
        
        result = self._execute_query(query, params)
        return [self._map_result_to_user(row) for row in result.get('rows', [])]
    
    def save(self, user: User) -> User:
        """Save user to database"""
        user_dict = user.to_dict()
        # Convert roles list to JSON string for database storage
        user_dict['roles'] = json.dumps(user.roles)
        user_dict['profile_data'] = json.dumps(user.profile_data)
        
        result = super().save(user_dict)
        
        # Update user object with saved data
        if result.get('id'):
            user.id = result['id']
        if result.get('created_at'):
            user.created_at = result['created_at']
        if result.get('updated_at'):
            user.updated_at = result['updated_at']
        
        return user
    
    def _map_result_to_user(self, result: Dict[str, Any]) -> User:
        """Map database result to User object"""
        roles = json.loads(result.get('roles', '[]')) if result.get('roles') else []
        profile_data = json.loads(result.get('profile_data', '{}')) if result.get('profile_data') else {}
        
        return User(
            id=result.get('id'),
            username=result.get('username'),
            email=result.get('email'),
            password_hash=result.get('password_hash'),
            first_name=result.get('first_name'),
            last_name=result.get('last_name'),
            created_at=result.get('created_at'),
            updated_at=result.get('updated_at'),
            last_login=result.get('last_login'),
            is_active=result.get('is_active', True),
            roles=roles,
            profile_data=profile_data
        )


class ProductRepository(BaseRepository):
    """Repository for product data access"""
    
    def __init__(self, connection_pool: ConnectionPool):
        super().__init__(connection_pool)
        self.table_name = "products"
    
    def find_by_category(self, category: str) -> List[Product]:
        """Find products by category"""
        query = f"SELECT * FROM {self.table_name} WHERE category = :category"
        params = {'category': category}
        
        result = self._execute_query(query, params)
        return [self._map_result_to_product(row) for row in result.get('rows', [])]
    
    def find_by_sku(self, sku: str) -> Optional[Product]:
        """Find product by SKU"""
        query = f"SELECT * FROM {self.table_name} WHERE sku = :sku"
        params = {'sku': sku}
        
        result = self._execute_query(query, params)
        if result.get('rows'):
            return self._map_result_to_product(result['rows'][0])
        return None
    
    def search(self, search_term: str) -> List[Product]:
        """Search products by name or description"""
        query = f"""
        SELECT * FROM {self.table_name} 
        WHERE name LIKE :term OR description LIKE :term
        """
        params = {'term': f'%{search_term}%'}
        
        result = self._execute_query(query, params)
        return [self._map_result_to_product(row) for row in result.get('rows', [])]
    
    def find_low_stock(self, threshold: int) -> List[Product]:
        """Find products with stock below threshold"""
        query = f"""
        SELECT * FROM {self.table_name} 
        WHERE stock_quantity <= :threshold AND is_available = 1
        """
        params = {'threshold': threshold}
        
        result = self._execute_query(query, params)
        return [self._map_result_to_product(row) for row in result.get('rows', [])]
    
    def save(self, product: Product) -> Product:
        """Save product to database"""
        product_dict = product.to_dict()
        # Convert tags list to JSON string for database storage
        product_dict['tags'] = json.dumps(product.tags)
        product_dict['metadata'] = json.dumps(product.metadata)
        
        result = super().save(product_dict)
        
        # Update product object with saved data
        if result.get('id'):
            product.id = result['id']
        if result.get('created_at'):
            product.created_at = result['created_at']
        if result.get('updated_at'):
            product.updated_at = result['updated_at']
        
        return product
    
    def _map_result_to_product(self, result: Dict[str, Any]) -> Product:
        """Map database result to Product object"""
        tags = json.loads(result.get('tags', '[]')) if result.get('tags') else []
        metadata = json.loads(result.get('metadata', '{}')) if result.get('metadata') else {}
        
        return Product(
            id=result.get('id'),
            name=result.get('name'),
            description=result.get('description'),
            price=result.get('price'),
            category=result.get('category'),
            sku=result.get('sku'),
            stock_quantity=result.get('stock_quantity', 0),
            is_available=result.get('is_available', True),
            created_at=result.get('created_at'),
            updated_at=result.get('updated_at'),
            tags=tags,
            metadata=metadata
        )


def hash_user_password(password: str) -> str:
    """Utility function to hash passwords"""
    salt = "app_salt_2024"
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


def validate_business_rules(entity_type: str, data: Dict[str, Any]) -> List[str]:
    """Validate business rules for entities"""
    errors = []
    
    if entity_type == 'user':
        if not data.get('username'):
            errors.append("Username is required")
        if not data.get('email'):
            errors.append("Email is required")
        if len(data.get('username', '')) < 3:
            errors.append("Username must be at least 3 characters")
    
    elif entity_type == 'product':
        if not data.get('name'):
            errors.append("Product name is required")
        if data.get('price', 0) < 0:
            errors.append("Price cannot be negative")
        if data.get('stock_quantity', 0) < 0:
            errors.append("Stock quantity cannot be negative")
    
    return errors
