"""
Pytest configuration and fixtures for auth_service tests.
"""
import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


@pytest.fixture
def api_client():
    """Return API client for testing."""
    return APIClient()


@pytest.fixture
def user_data():
    """Return sample user data."""
    return {
        'email': 'test@example.com',
        'password': 'testpassword123',
        'first_name': 'Test',
        'last_name': 'User',
    }


@pytest.fixture
def user(user_data):
    """Create and return a test user."""
    return User.objects.create_user(**user_data)


@pytest.fixture
def admin_user():
    """Create and return an admin user."""
    return User.objects.create_user(
        email='admin@example.com',
        password='adminpassword123',
        first_name='Admin',
        last_name='User',
        is_staff=True,
        role=User.UserRole.ADMIN
    )


@pytest.fixture
def verified_user(user):
    """Create and return a verified user."""
    user.is_verified = True
    user.save()
    return user


@pytest.fixture
def authenticated_client(api_client, user):
    """Return API client with authenticated user."""
    from apps.authentication.tokens import create_tokens_for_user
    
    tokens = create_tokens_for_user(user=user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
    return api_client


@pytest.fixture
def admin_client(api_client, admin_user):
    """Return API client with authenticated admin user."""
    from apps.authentication.tokens import create_tokens_for_user
    
    tokens = create_tokens_for_user(user=admin_user)
    api_client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access_token"]}')
    return api_client


@pytest.fixture
def refresh_token(user):
    """Create and return a refresh token for user."""
    from apps.authentication.tokens import RefreshTokenClass
    return RefreshTokenClass(user=user)


@pytest.fixture
def access_token(user):
    """Create and return an access token for user."""
    from apps.authentication.tokens import AccessToken
    return AccessToken(user=user)
