# tests/integration/test_user_auth.py

# This file contains user authentication integration tests

import pytest
from uuid import UUID
import pydantic_core
from sqlalchemy.exc import IntegrityError
from app.models.user import User


class TestUserCore:
    """Test core user functionality - password handling, JWT tokens, and model creation"""
    
    def test_password_operations(self):
        """Test complete password hashing and verification workflow"""
        correct_password = "TestPassword123"
        wrong_password = "WrongPassword123"
        
        # Test hashing
        hashed_password = User.hash_password(correct_password)
        assert hashed_password != correct_password
        assert len(hashed_password) > 0
        assert hashed_password.startswith("$2b$")  # bcrypt format
        
        # Test verification - success and failure
        user = User(
            first_name="Test",
            last_name="User",
            email="test@example.com",
            username="testuser",
            password=hashed_password
        )
        
        assert user.verify_password(correct_password) is True
        assert user.verify_password(wrong_password) is False
    
    def test_jwt_token_operations(self):
        """Test JWT token creation and verification workflow"""
        test_user_id = UUID("12345678-1234-5678-1234-567812345678")
        test_data = {"sub": str(test_user_id)}
        
        # Test token creation
        token = User.create_access_token(test_data)
        assert isinstance(token, str)
        assert len(token) > 0
        assert "." in token  # JWT format has dots
        
        # Test valid token verification
        verified_id = User.verify_token(token)
        assert verified_id == test_user_id
        
        # Test invalid token verification
        invalid_token = "invalid.jwt.token"
        assert User.verify_token(invalid_token) is None
    
    def test_user_model_and_representation(self):
        """Test User model creation and string representation"""
        import uuid
        user_id = uuid.uuid4()
        
        user = User(
            id=user_id,
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            username="johndoe",
            password="hashedpassword",
            is_active=True,
            is_verified=False
        )
        
        # Test model attributes
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.email == "john.doe@example.com"
        assert user.username == "johndoe"
        assert user.is_active is True
        assert user.is_verified is False
        assert isinstance(user.id, UUID)
        assert user.id == user_id
        
        # Test string representation
        repr_str = repr(user)
        assert "John Doe" in repr_str
        assert "john.doe@example.com" in repr_str


class TestUserRegistration:
    """Test user registration functionality with validation and constraints"""
    
    def test_register_valid_user(self, db_session):
        """Test successful user registration"""
        user_data = {
            "first_name": "New",
            "last_name": "User",
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "Password123"
        }
        
        user = User.register(db_session, user_data)
        
        assert user.first_name == "New"
        assert user.last_name == "User"
        assert user.email == "newuser@example.com"
        assert user.username == "newuser"
        assert user.is_active is True
        assert user.is_verified is False
        assert user.verify_password("Password123")
    
    def test_register_validation_errors(self, db_session):
        """Test registration validation - password length and duplicate constraints"""
        # Test password too short
        short_password_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "test@example.com",
            "username": "testuser",
            "password": "Pass1"  # Only 5 characters
        }
        
        with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
            User.register(db_session, short_password_data)
        
        # Create first user for duplicate testing
        valid_user_data = {
            "first_name": "First",
            "last_name": "User",
            "email": "duplicate@example.com",
            "username": "duplicateuser",
            "password": "Password123"
        }
        User.register(db_session, valid_user_data)
        db_session.commit()
        
        # Test duplicate email
        duplicate_email_data = {
            "first_name": "Second",
            "last_name": "User",
            "email": "duplicate@example.com",  # Same email
            "username": "differentuser",
            "password": "Password123"
        }
        
        with pytest.raises(ValueError, match="Username or email already exists"):
            User.register(db_session, duplicate_email_data)
        
        # Test duplicate username
        duplicate_username_data = {
            "first_name": "Third",
            "last_name": "User",
            "email": "different@example.com",
            "username": "duplicateuser",  # Same username
            "password": "Password123"
        }
        
        with pytest.raises(ValueError, match="Username or email already exists"):
            User.register(db_session, duplicate_username_data)


class TestUserAuthentication:
    """Test complete user authentication workflow - success and failure scenarios"""
    
    @pytest.mark.parametrize("login_field,login_value,email,username", [
        ("username", "authuser", "authuser@example.com", "authuser"),
        ("email", "emailuser@example.com", "emailuser@example.com", "emailuser")
    ])
    def test_authenticate_success(self, db_session, login_field, login_value, email, username):
        """Test successful authentication using username or email"""
        # Register user with unique data for each test case
        user_data = {
            "first_name": "Auth",
            "last_name": "Test",
            "email": email,
            "username": username, 
            "password": "Password123"
        }
        User.register(db_session, user_data)
        db_session.commit()
        
        # Authenticate
        result = User.authenticate(db_session, login_value, "Password123")
        
        assert result is not None
        assert "access_token" in result
        assert "token_type" in result
        assert result["token_type"] == "bearer"
        assert "user" in result
        
        if login_field == "username":
            assert result["user"]["username"] == username
        else:
            assert result["user"]["email"] == email
    
    def test_authenticate_failures(self, db_session):
        """Test authentication failure scenarios - wrong password and nonexistent user"""
        # Register user for wrong password test
        user_data = {
            "first_name": "Test",
            "last_name": "User",
            "email": "testuser@example.com",
            "username": "testuser",
            "password": "CorrectPass123"
        }
        User.register(db_session, user_data)
        db_session.commit()
        
        # Test wrong password
        result = User.authenticate(db_session, "testuser", "WrongPass123")
        assert result is None
        
        # Test nonexistent user
        result = User.authenticate(db_session, "nonexistent", "Password123")
        assert result is None