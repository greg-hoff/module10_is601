# tests/integration/test_dependencies.py

# This file contains dependency integration tests

import pytest
from unittest.mock import MagicMock, patch, ANY
from fastapi import HTTPException, status
from app.auth.dependencies import get_current_user, get_current_active_user
from app.schemas.user import UserResponse
from app.models.user import User
from uuid import uuid4
from datetime import datetime


class TestGetCurrentUser:
    """Test get_current_user dependency functionality"""
    
    def _create_mock_user(self, user_id, is_active=True):
        """Helper method to create consistent mock user objects"""
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.first_name = "Test"
        mock_user.last_name = "User"
        mock_user.email = "test@example.com"
        mock_user.username = "testuser"
        mock_user.is_active = is_active
        mock_user.is_verified = True
        mock_user.created_at = datetime.utcnow()
        mock_user.updated_at = datetime.utcnow()
        return mock_user
    
    def test_get_current_user_success(self):
        """Test successful user retrieval from valid JWT token with schema validation"""
        user_id = uuid4()
        mock_db = MagicMock()
        valid_token = "valid.jwt.token"
        
        # Create mock user
        mock_user = self._create_mock_user(user_id)
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Mock User.verify_token to return valid user_id
        with patch.object(User, 'verify_token', return_value=user_id) as mock_verify:
            result = get_current_user(mock_db, valid_token)
            
            # Verify token verification and database query
            mock_verify.assert_called_once_with(valid_token)
            mock_db.query.assert_called_once_with(User)
            
            # Verify result is UserResponse with correct schema
            assert isinstance(result, UserResponse)
            assert result.username == "testuser"
            assert result.email == "test@example.com"
            assert result.is_active is True
            
            # Verify all required UserResponse fields are present
            assert hasattr(result, 'id')
            assert hasattr(result, 'first_name')
            assert hasattr(result, 'last_name')
    
    @pytest.mark.parametrize("scenario,token_return,db_return,error_msg", [
        ("invalid_token", None, None, "Invalid token scenarios"),
        ("user_not_found", uuid4(), None, "Valid token but user not in DB"),
    ])
    def test_get_current_user_failures(self, scenario, token_return, db_return, error_msg):
        """Test user retrieval failure scenarios - invalid tokens and missing users"""
        mock_db = MagicMock()
        test_token = f"{scenario}.jwt.token"
        
        # Setup database mock
        mock_db.query.return_value.filter.return_value.first.return_value = db_return
        
        with patch.object(User, 'verify_token', return_value=token_return):
            with pytest.raises(HTTPException) as exc_info:
                get_current_user(mock_db, test_token)
            
            # Verify correct HTTP exception details
            assert exc_info.value.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Could not validate credentials" in exc_info.value.detail
            assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}
    
    def test_get_current_user_database_error(self):
        """Test user retrieval handles database errors gracefully"""
        user_id = uuid4()
        mock_db = MagicMock()
        valid_token = "valid.jwt.token"
        
        # Mock database query to raise an exception
        mock_db.query.side_effect = Exception("Database connection error")
        
        # Mock User.verify_token to return valid user_id
        with patch.object(User, 'verify_token', return_value=user_id):
            with pytest.raises(Exception, match="Database connection error"):
                get_current_user(mock_db, valid_token)


class TestGetCurrentActiveUser:
    """Test get_current_active_user dependency functionality"""
    
    @pytest.mark.parametrize("is_active,is_verified,should_succeed", [
        (True, True, True),      # Active + verified = success
        (True, False, True),     # Active + unverified = success (verification irrelevant)
        (False, True, False),    # Inactive + verified = fail  
        (False, False, False),   # Inactive + unverified = fail
    ])
    def test_get_current_active_user_scenarios(self, is_active, is_verified, should_succeed):
        """Test all combinations of user active/verified status"""
        test_user = UserResponse(
            id=uuid4(),
            first_name="Test",
            last_name="User",
            email=f"test{is_active}{is_verified}@example.com",
            username=f"user{is_active}{is_verified}",
            is_active=is_active,
            is_verified=is_verified,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        if should_succeed:
            result = get_current_active_user(test_user)
            assert result == test_user
            assert result.is_active is True
        else:
            with pytest.raises(HTTPException) as exc_info:
                get_current_active_user(test_user)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert exc_info.value.detail == "Inactive user"


class TestDependencyIntegration:
    """Test complete integration workflow from token to active user"""
    
    def test_dependency_chain_complete_workflow(self):
        """Test complete dependency chain with both success and failure scenarios"""
        user_id = uuid4()
        mock_db = MagicMock()
        valid_token = "valid.jwt.token"
        
        # Test successful chain with active user
        active_user = self._create_test_user(user_id, is_active=True)
        mock_db.query.return_value.filter.return_value.first.return_value = active_user
        
        with patch.object(User, 'verify_token', return_value=user_id):
            # Complete successful chain
            current_user = get_current_user(mock_db, valid_token)
            active_result = get_current_active_user(current_user)
            
            assert isinstance(current_user, UserResponse)
            assert isinstance(active_result, UserResponse)
            assert current_user == active_result
            assert active_result.is_active is True
        
        # Test chain failure with inactive user
        inactive_user = self._create_test_user(user_id, is_active=False)
        mock_db.query.return_value.filter.return_value.first.return_value = inactive_user
        
        with patch.object(User, 'verify_token', return_value=user_id):
            # First step succeeds
            current_user = get_current_user(mock_db, valid_token)
            assert current_user.is_active is False
            
            # Second step fails
            with pytest.raises(HTTPException) as exc_info:
                get_current_active_user(current_user)
            
            assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
            assert exc_info.value.detail == "Inactive user"
    
    def _create_test_user(self, user_id, is_active=True):
        """Helper method to create test users for integration testing"""
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.first_name = "Integration"
        mock_user.last_name = "Test"
        mock_user.email = "integration@example.com"
        mock_user.username = "integrationtest"
        mock_user.is_active = is_active
        mock_user.is_verified = True
        mock_user.created_at = datetime.utcnow()
        mock_user.updated_at = datetime.utcnow()
        return mock_user