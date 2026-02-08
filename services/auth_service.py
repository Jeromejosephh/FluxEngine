"""Authentication service"""
from datetime import datetime, timedelta
from typing import Optional
import jwt
from passlib.context import CryptContext

from schemas.user import UserCreate
from schemas.auth import Token, TokenData
from models.user import User
from services.duckdb_service import DuckDBService
from utils.config import settings
from utils.exceptions import AuthenticationException

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    """Service for authentication operations"""
    
    def __init__(self):
        self.db_service = DuckDBService()
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        return pwd_context.hash(password)
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a password against a hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """
        Create a JWT access token
        
        Args:
            data: Payload data to encode
            expires_delta: Optional expiration time delta
            
        Returns:
            Encoded JWT token
        """
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        return encoded_jwt
    
    def decode_token(self, token: str) -> TokenData:
        """
        Decode and validate a JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            TokenData with user information
            
        Raises:
            AuthenticationException: If token is invalid
        """
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            user_id: int = payload.get("sub")
            email: str = payload.get("email")
            role: str = payload.get("role")
            
            if user_id is None:
                raise AuthenticationException("Invalid token")
            
            return TokenData(user_id=user_id, email=email, role=role)
        
        except jwt.ExpiredSignatureError:
            raise AuthenticationException("Token has expired")
        except jwt.PyJWTError:
            raise AuthenticationException("Invalid token")
    
    def create_user(self, user_data: UserCreate) -> User:
        """
        Create a new user

        Args:
            user_data: User creation data

        Returns:
            Created User object

        Raises:
            ValueError: If user with email already exists
        """
        # Check if user already exists
        existing_user = self.get_user_by_email(user_data.email)
        if existing_user:
            raise ValueError("User with this email already exists")

        # Hash password
        hashed_password = self.hash_password(user_data.password)

        # Create user in database
        user = self.db_service.create_user(
            email=user_data.email,
            hashed_password=hashed_password,
            full_name=user_data.full_name,
            role=user_data.role
        )

        return user
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Get user by email

        Args:
            email: User email address

        Returns:
            User object if found, None otherwise
        """
        return self.db_service.get_user_by_email(email)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Get user by ID

        Args:
            user_id: User ID

        Returns:
            User object if found, None otherwise
        """
        return self.db_service.get_user_by_id(user_id)
    
    def authenticate_user(self, email: str, password: str) -> Token:
        """
        Authenticate user and return JWT token
        
        Args:
            email: User email
            password: User password
            
        Returns:
            Token with access token
            
        Raises:
            AuthenticationException: If authentication fails
        """
        user = self.get_user_by_email(email)
        
        if not user:
            raise AuthenticationException("Invalid email or password")
        
        if not self.verify_password(password, user.hashed_password):
            raise AuthenticationException("Invalid email or password")
        
        if not user.is_active:
            raise AuthenticationException("User account is inactive")
        
        # Create access token
        access_token = self.create_access_token(
            data={"sub": user.id, "email": user.email, "role": user.role}
        )
        
        return Token(access_token=access_token)
    
    def get_current_user(self, token: str) -> User:
        """
        Get current user from JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            User object
            
        Raises:
            AuthenticationException: If token is invalid or user not found
        """
        token_data = self.decode_token(token)
        
        user = self.get_user_by_id(token_data.user_id)
        
        if not user:
            raise AuthenticationException("User not found")
        
        return user
