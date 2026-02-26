"""
Unit tests for authentication endpoints
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from src.backend.routers.auth import hash_password, login, check_session
from fastapi import HTTPException


class TestHashPassword:
    """Test password hashing function"""
    
    def test_hash_password_consistent(self):
        """Test that the same password produces the same hash"""
        password = "test_password_123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        assert hash1 == hash2
    
    def test_hash_password_different_for_different_inputs(self):
        """Test that different passwords produce different hashes"""
        hash1 = hash_password("password1")
        hash2 = hash_password("password2")
        assert hash1 != hash2
    
    def test_hash_password_returns_string(self):
        """Test that hash_password returns a string"""
        result = hash_password("test")
        assert isinstance(result, str)
    
    def test_hash_password_returns_valid_sha256(self):
        """Test that the returned hash is a valid SHA-256 hex string"""
        result = hash_password("test")
        assert len(result) == 64  # SHA-256 hex is 64 characters
        assert all(c in "0123456789abcdef" for c in result)


class TestLoginEndpoint:
    """Test the login endpoint"""
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_login_success(self, mock_collection):
        """Test successful login with correct credentials"""
        username = "teacher_001"
        password = "correct_password"
        hashed_password = hash_password(password)
        
        mock_teacher = {
            "_id": username,
            "username": username,
            "password": hashed_password,
            "display_name": "John Doe",
            "role": "teacher"
        }
        
        mock_collection.find_one.return_value = mock_teacher
        
        result = login(username, password)
        
        assert result["username"] == username
        assert result["display_name"] == "John Doe"
        assert result["role"] == "teacher"
        assert "password" not in result
        mock_collection.find_one.assert_called_once_with({"_id": username})
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_login_invalid_password(self, mock_collection):
        """Test login with incorrect password"""
        username = "teacher_001"
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        
        mock_teacher = {
            "_id": username,
            "username": username,
            "password": hash_password(correct_password),
            "display_name": "John Doe",
            "role": "teacher"
        }
        
        mock_collection.find_one.return_value = mock_teacher
        
        with pytest.raises(HTTPException) as exc_info:
            login(username, wrong_password)
        
        assert exc_info.value.status_code == 401
        assert "Invalid username or password" in exc_info.value.detail
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_login_user_not_found(self, mock_collection):
        """Test login with non-existent username"""
        username = "nonexistent_user"
        password = "some_password"
        
        mock_collection.find_one.return_value = None
        
        with pytest.raises(HTTPException) as exc_info:
            login(username, password)
        
        assert exc_info.value.status_code == 401
        assert "Invalid username or password" in exc_info.value.detail
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_login_does_not_return_password(self, mock_collection):
        """Test that login response does not contain password"""
        username = "teacher_001"
        password = "correct_password"
        hashed_password = hash_password(password)
        
        mock_teacher = {
            "_id": username,
            "username": username,
            "password": hashed_password,
            "display_name": "John Doe",
            "role": "teacher"
        }
        
        mock_collection.find_one.return_value = mock_teacher
        
        result = login(username, password)
        
        assert "password" not in result
        assert "display_name" in result
        assert "role" in result


class TestCheckSessionEndpoint:
    """Test the check-session endpoint"""
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_check_session_valid_teacher(self, mock_collection):
        """Test checking session for an existing teacher"""
        username = "teacher_001"
        
        mock_teacher = {
            "_id": username,
            "username": username,
            "password": "hashed_password",
            "display_name": "Jane Smith",
            "role": "teacher"
        }
        
        mock_collection.find_one.return_value = mock_teacher
        
        result = check_session(username)
        
        assert result["username"] == username
        assert result["display_name"] == "Jane Smith"
        assert result["role"] == "teacher"
        assert "password" not in result
        mock_collection.find_one.assert_called_once_with({"_id": username})
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_check_session_teacher_not_found(self, mock_collection):
        """Test checking session for a non-existent teacher"""
        username = "nonexistent_teacher"
        
        mock_collection.find_one.return_value = None
        
        with pytest.raises(HTTPException) as exc_info:
            check_session(username)
        
        assert exc_info.value.status_code == 404
        assert "Teacher not found" in exc_info.value.detail
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_check_session_does_not_return_password(self, mock_collection):
        """Test that check_session response does not contain password"""
        username = "teacher_001"
        
        mock_teacher = {
            "_id": username,
            "username": username,
            "password": "hashed_password",
            "display_name": "Jane Smith",
            "role": "teacher"
        }
        
        mock_collection.find_one.return_value = mock_teacher
        
        result = check_session(username)
        
        assert "password" not in result
        assert "username" in result
        assert "display_name" in result
        assert "role" in result


class TestIntegration:
    """Integration tests for authentication flow"""
    
    @patch('src.backend.routers.auth.teachers_collection')
    def test_login_then_check_session_flow(self, mock_collection):
        """Test the flow of logging in and then checking the session"""
        username = "teacher_001"
        password = "test_password"
        hashed_password = hash_password(password)
        
        mock_teacher = {
            "_id": username,
            "username": username,
            "password": hashed_password,
            "display_name": "John Doe",
            "role": "admin"
        }
        
        mock_collection.find_one.return_value = mock_teacher
        
        # Simulate login
        login_result = login(username, password)
        assert login_result["username"] == username
        
        # Simulate session check
        session_result = check_session(username)
        assert session_result["username"] == username
        assert session_result["display_name"] == login_result["display_name"]
