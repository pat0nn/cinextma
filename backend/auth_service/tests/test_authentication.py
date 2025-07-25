"""
Tests for authentication endpoints.
"""
import pytest
from datetime import timedelta
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import status

from apps.authentication.models import RefreshToken, EmailVerificationToken

User = get_user_model()


@pytest.mark.django_db
class TestRegisterView:
    """Test user registration endpoint."""
    
    def test_register_success(self, api_client):
        """Test successful user registration."""
        url = reverse('authentication:register')
        data = {
            'email': 'newuser@example.com',
            'password': 'newpassword123',
            'password_confirm': 'newpassword123',
            'first_name': 'New',
            'last_name': 'User',
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_201_CREATED
        assert 'user_id' in response.data
        assert response.data['email'] == 'newuser@example.com'
        
        # Check user was created
        user = User.objects.get(email='newuser@example.com')
        assert user.first_name == 'New'
        assert user.last_name == 'User'
        assert not user.is_verified
    
    def test_register_password_mismatch(self, api_client):
        """Test registration with password mismatch."""
        url = reverse('authentication:register')
        data = {
            'email': 'newuser@example.com',
            'password': 'newpassword123',
            'password_confirm': 'differentpassword',
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    def test_register_duplicate_email(self, api_client, user):
        """Test registration with existing email."""
        url = reverse('authentication:register')
        data = {
            'email': user.email,
            'password': 'newpassword123',
            'password_confirm': 'newpassword123',
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestLoginView:
    """Test user login endpoint."""
    
    def test_login_success(self, api_client, user):
        """Test successful login."""
        url = reverse('authentication:login')
        data = {
            'email': user.email,
            'password': 'testpassword123',
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'tokens' in response.data
        assert 'access_token' in response.data['tokens']
        assert 'refresh_token' in response.data['tokens']
    
    def test_login_invalid_credentials(self, api_client, user):
        """Test login with invalid credentials."""
        url = reverse('authentication:login')
        data = {
            'email': user.email,
            'password': 'wrongpassword',
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    def test_login_inactive_user(self, api_client, user):
        """Test login with inactive user."""
        user.is_active = False
        user.save()
        
        url = reverse('authentication:login')
        data = {
            'email': user.email,
            'password': 'testpassword123',
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestLogoutView:
    """Test user logout endpoint."""
    
    def test_logout_success(self, authenticated_client):
        """Test successful logout."""
        url = reverse('authentication:logout')
        
        response = authenticated_client.post(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'message' in response.data
    
    def test_logout_unauthenticated(self, api_client):
        """Test logout without authentication."""
        url = reverse('authentication:logout')
        
        response = api_client.post(url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestRefreshTokenView:
    """Test token refresh endpoint."""
    
    def test_refresh_success(self, api_client, user):
        """Test successful token refresh."""
        from apps.authentication.tokens import create_tokens_for_user
        
        tokens = create_tokens_for_user(user=user)
        
        url = reverse('authentication:refresh')
        data = {
            'refresh_token': tokens['refresh_token']
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'tokens' in response.data
        assert 'access_token' in response.data['tokens']
    
    def test_refresh_invalid_token(self, api_client):
        """Test refresh with invalid token."""
        url = reverse('authentication:refresh')
        data = {
            'refresh_token': 'invalid_token'
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestMeView:
    """Test current user endpoint."""
    
    def test_me_success(self, authenticated_client, user):
        """Test getting current user info."""
        url = reverse('authentication:me')
        
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == user.email
        assert response.data['id'] == str(user.id)
    
    def test_me_unauthenticated(self, api_client):
        """Test getting current user info without authentication."""
        url = reverse('authentication:me')
        
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_me_update(self, authenticated_client, user):
        """Test updating current user info."""
        url = reverse('authentication:me')
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
        }
        
        response = authenticated_client.put(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['first_name'] == 'Updated'
        assert response.data['last_name'] == 'Name'


@pytest.mark.django_db
class TestPasswordResetView:
    """Test password reset endpoints."""
    
    def test_password_reset_request(self, api_client, user):
        """Test password reset request."""
        url = reverse('authentication:password_reset_request')
        data = {
            'email': user.email
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'message' in response.data
    
    def test_password_reset_request_nonexistent_email(self, api_client):
        """Test password reset request with non-existent email."""
        url = reverse('authentication:password_reset_request')
        data = {
            'email': 'nonexistent@example.com'
        }
        
        response = api_client.post(url, data)
        
        # Should still return success to not reveal if email exists
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
class TestEmailVerificationView:
    """Test email verification endpoints."""
    
    def test_email_verification_success(self, api_client, user):
        """Test successful email verification."""
        # Create verification token
        token = EmailVerificationToken.objects.create(
            user=user,
            token='test_token',
            expires_at=timezone.now() + timedelta(hours=24)
        )
        
        url = reverse('authentication:email_verify')
        data = {
            'token': 'test_token'
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        
        # Check user is verified
        user.refresh_from_db()
        assert user.is_verified
    
    def test_email_verification_invalid_token(self, api_client):
        """Test email verification with invalid token."""
        url = reverse('authentication:email_verify')
        data = {
            'token': 'invalid_token'
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
