# tests/integration/test_schema_base.py

import pytest
from pydantic import ValidationError
from app.schemas.base import UserBase, PasswordMixin, UserCreate, UserLogin


class TestUserBase:
    """Test cases for UserBase schema"""
    
    def test_valid_user_base(self):
        """Test creating a valid UserBase"""
        user = UserBase(
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            username="johndoe"
        )
        assert user.first_name == "John"
        assert user.last_name == "Doe"
        assert user.email == "john.doe@example.com"
        assert user.username == "johndoe"
    
    def test_user_base_email_validation(self):
        """Test UserBase validates email format"""
        with pytest.raises(ValidationError):
            UserBase(
                first_name="John",
                last_name="Doe",
                email="invalid-email",
                username="johndoe"
            )
    
    def test_user_base_username_length(self):
        """Test UserBase validates username length"""
        # Test username too short
        with pytest.raises(ValidationError):
            UserBase(
                first_name="John",
                last_name="Doe",
                email="john.doe@example.com",
                username="jo"  # Less than 3 characters
            )


class TestPasswordMixin:
    """Test cases for PasswordMixin schema"""
    
    def test_valid_password(self):
        """Test creating valid password"""
        password_obj = PasswordMixin(password="SecurePass123")
        assert password_obj.password == "SecurePass123"
    
    def test_password_too_short(self):
        """Test password length validation"""
        with pytest.raises(ValueError, match="Password must be at least 6 characters long"):
            PasswordMixin(password="12345")
    
    def test_password_missing_uppercase(self):
        """Test password uppercase requirement"""
        with pytest.raises(ValueError, match="Password must contain at least one uppercase letter"):
            PasswordMixin(password="lowercase123")
    
    def test_password_missing_lowercase(self):
        """Test password lowercase requirement"""
        with pytest.raises(ValueError, match="Password must contain at least one lowercase letter"):
            PasswordMixin(password="UPPERCASE123")
    
    def test_password_missing_digit(self):
        """Test password digit requirement"""
        with pytest.raises(ValueError, match="Password must contain at least one digit"):
            PasswordMixin(password="NoDigitsHere")


class TestUserCreate:
    """Test cases for UserCreate schema"""
    
    def test_valid_user_create(self):
        """Test creating a valid UserCreate"""
        user = UserCreate(
            first_name="John",
            last_name="Doe",
            email="john.doe@example.com",
            username="johndoe",
            password="SecurePass123"
        )
        assert user.first_name == "John"
        assert user.password == "SecurePass123"


class TestUserLogin:
    """Test cases for UserLogin schema"""
    
    def test_valid_user_login(self):
        """Test creating a valid UserLogin"""
        login = UserLogin(
            username="johndoe123",
            password="SecurePass123"
        )
        assert login.username == "johndoe123"
        assert login.password == "SecurePass123"
