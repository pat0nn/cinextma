"""
Tests for Google OAuth functionality.
"""
import pytest
from unittest.mock import patch, MagicMock
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status

from apps.authentication.oauth import GoogleOAuthService, google_oauth_login

User = get_user_model()


@pytest.mark.django_db
class TestGoogleOAuthService:
    """Test Google OAuth service."""
    
    @patch('apps.authentication.oauth.settings')
    def test_google_oauth_service_init(self, mock_settings):
        """Test GoogleOAuthService initialization."""
        mock_settings.GOOGLE_OAUTH_CLIENT_ID = 'test_client_id'
        mock_settings.GOOGLE_OAUTH_CLIENT_SECRET = 'test_client_secret'
        mock_settings.GOOGLE_OAUTH_REDIRECT_URI = 'http://localhost:8000/callback/'
        
        service = GoogleOAuthService()
        
        assert service.client_id == 'test_client_id'
        assert service.client_secret == 'test_client_secret'
        assert service.redirect_uri == 'http://localhost:8000/callback/'
    
    @patch('apps.authentication.oauth.settings')
    def test_google_oauth_service_missing_credentials(self, mock_settings):
        """Test GoogleOAuthService with missing credentials."""
        mock_settings.GOOGLE_OAUTH_CLIENT_ID = ''
        mock_settings.GOOGLE_OAUTH_CLIENT_SECRET = ''
        
        with pytest.raises(ValueError, match="Google OAuth credentials not configured"):
            GoogleOAuthService()
    
    @patch('apps.authentication.oauth.Flow')
    @patch('apps.authentication.oauth.settings')
    def test_get_authorization_url(self, mock_settings, mock_flow):
        """Test getting authorization URL."""
        mock_settings.GOOGLE_OAUTH_CLIENT_ID = 'test_client_id'
        mock_settings.GOOGLE_OAUTH_CLIENT_SECRET = 'test_client_secret'
        mock_settings.GOOGLE_OAUTH_REDIRECT_URI = 'http://localhost:8000/callback/'
        
        mock_flow_instance = MagicMock()
        mock_flow_instance.authorization_url.return_value = ('http://auth.url', 'state')
        mock_flow.from_client_config.return_value = mock_flow_instance
        
        service = GoogleOAuthService()
        auth_url = service.get_authorization_url('test_state')
        
        assert auth_url == 'http://auth.url'
        mock_flow_instance.authorization_url.assert_called_once()
    
    @patch('apps.authentication.oauth.id_token')
    @patch('apps.authentication.oauth.settings')
    def test_verify_id_token_success(self, mock_settings, mock_id_token):
        """Test successful ID token verification."""
        mock_settings.GOOGLE_OAUTH_CLIENT_ID = 'test_client_id'
        mock_settings.GOOGLE_OAUTH_CLIENT_SECRET = 'test_client_secret'
        mock_settings.GOOGLE_OAUTH_REDIRECT_URI = 'http://localhost:8000/callback/'
        
        mock_id_token.verify_oauth2_token.return_value = {
            'iss': 'accounts.google.com',
            'email': 'test@gmail.com',
            'given_name': 'Test',
            'family_name': 'User'
        }
        
        service = GoogleOAuthService()
        user_info = service.verify_id_token('test_token')
        
        assert user_info['email'] == 'test@gmail.com'
        assert user_info['given_name'] == 'Test'
    
    @patch('apps.authentication.oauth.requests')
    @patch('apps.authentication.oauth.settings')
    def test_get_user_info_from_token(self, mock_settings, mock_requests):
        """Test getting user info from access token."""
        mock_settings.GOOGLE_OAUTH_CLIENT_ID = 'test_client_id'
        mock_settings.GOOGLE_OAUTH_CLIENT_SECRET = 'test_client_secret'
        mock_settings.GOOGLE_OAUTH_REDIRECT_URI = 'http://localhost:8000/callback/'
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'email': 'test@gmail.com',
            'given_name': 'Test',
            'family_name': 'User'
        }
        mock_requests.get.return_value = mock_response
        
        service = GoogleOAuthService()
        user_info = service.get_user_info_from_token('access_token')
        
        assert user_info['email'] == 'test@gmail.com'


@pytest.mark.django_db
class TestGoogleOAuthViews:
    """Test Google OAuth views."""
    
    @patch('apps.authentication.views.google_oauth_get_auth_url')
    def test_google_oauth_url_view(self, mock_get_auth_url, api_client):
        """Test Google OAuth URL endpoint."""
        mock_get_auth_url.return_value = 'http://auth.url'
        
        url = reverse('authentication:google_oauth_url')
        data = {'state': 'test_state'}
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'auth_url' in response.data
        assert response.data['auth_url'] == 'http://auth.url'
    
    @patch('apps.authentication.views.google_oauth_login')
    def test_google_oauth_callback_success(self, mock_oauth_login, api_client):
        """Test successful Google OAuth callback."""
        mock_oauth_login.return_value = {
            'user_id': 'test_user_id',
            'email': 'test@gmail.com',
            'tokens': {
                'access_token': 'access_token',
                'refresh_token': 'refresh_token'
            },
            'is_new_user': True
        }
        
        url = reverse('authentication:google_oauth_callback')
        data = {
            'code': 'auth_code',
            'state': 'test_state'
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'user_id' in response.data
        assert 'tokens' in response.data
        assert response.data['email'] == 'test@gmail.com'
    
    @patch('apps.authentication.views.google_oauth_login')
    def test_google_oauth_callback_error(self, mock_oauth_login, api_client):
        """Test Google OAuth callback with error."""
        from django.core.exceptions import ValidationError
        mock_oauth_login.side_effect = ValidationError('OAuth error')
        
        url = reverse('authentication:google_oauth_callback')
        data = {
            'code': 'invalid_code',
        }
        
        response = api_client.post(url, data)
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'error' in response.data


@pytest.mark.django_db
class TestGoogleOAuthIntegration:
    """Test Google OAuth integration."""
    
    @patch('apps.authentication.oauth.GoogleOAuthService.exchange_code_for_token')
    @patch('apps.authentication.oauth.GoogleOAuthService.verify_id_token')
    def test_google_oauth_login_new_user(self, mock_verify_token, mock_exchange_token):
        """Test Google OAuth login with new user."""
        mock_exchange_token.return_value = {
            'access_token': 'access_token',
            'id_token': 'id_token'
        }
        
        mock_verify_token.return_value = {
            'email': 'newuser@gmail.com',
            'given_name': 'New',
            'family_name': 'User',
            'email_verified': True,
            'picture': 'http://avatar.url'
        }
        
        result = google_oauth_login(code='auth_code')
        
        assert 'user_id' in result
        assert result['email'] == 'newuser@gmail.com'
        assert 'tokens' in result
        
        # Check user was created
        user = User.objects.get(email='newuser@gmail.com')
        assert user.first_name == 'New'
        assert user.last_name == 'User'
        assert user.is_verified == True
    
    @patch('apps.authentication.oauth.GoogleOAuthService.exchange_code_for_token')
    @patch('apps.authentication.oauth.GoogleOAuthService.verify_id_token')
    def test_google_oauth_login_existing_user(self, mock_verify_token, mock_exchange_token, user):
        """Test Google OAuth login with existing user."""
        mock_exchange_token.return_value = {
            'access_token': 'access_token',
            'id_token': 'id_token'
        }
        
        mock_verify_token.return_value = {
            'email': user.email,
            'given_name': 'Test',
            'family_name': 'User',
            'email_verified': True
        }
        
        result = google_oauth_login(code='auth_code')
        
        assert result['user_id'] == str(user.id)
        assert result['email'] == user.email
        assert 'tokens' in result
