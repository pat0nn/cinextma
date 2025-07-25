"""
Google OAuth integration for authentication.
"""
import requests
import warnings
from typing import Dict, Any, Optional
from django.conf import settings
from django.core.exceptions import ValidationError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

from apps.users.services import user_create
from apps.users.selectors import user_get_by_email
from .tokens import create_tokens_for_user


class GoogleOAuthService:
    """
    Service for handling Google OAuth authentication.
    """
    
    def __init__(self):
        self.client_id = settings.GOOGLE_OAUTH_CLIENT_ID
        self.client_secret = settings.GOOGLE_OAUTH_CLIENT_SECRET
        self.redirect_uri = settings.GOOGLE_OAUTH_REDIRECT_URI
        
        if not all([self.client_id, self.client_secret]):
            raise ValueError("Google OAuth credentials not configured")
    
    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """
        Get Google OAuth authorization URL.
        """
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [self.redirect_uri],
                }
            },
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ],
            redirect_uri=self.redirect_uri
        )
        
        authorization_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            state=state
        )
        
        return authorization_url
    
    def exchange_code_for_token(self, code: str) -> Dict[str, Any]:
        """
        Exchange authorization code for access token.
        """
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": [self.redirect_uri],
                }
            },
            scopes=[
                'openid',
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile'
            ],
            redirect_uri=self.redirect_uri
        )
        
        # Suppress scope mismatch warnings from Google OAuth
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Scope has changed")
            flow.fetch_token(code=code)
        
        return {
            'access_token': flow.credentials.token,
            'refresh_token': flow.credentials.refresh_token,
            'id_token': flow.credentials.id_token,
        }
    
    def verify_id_token(self, id_token_str: str) -> Dict[str, Any]:
        """
        Verify Google ID token and extract user info.
        """
        try:
            # Verify the token with clock skew tolerance
            idinfo = id_token.verify_oauth2_token(
                id_token_str,
                google_requests.Request(),
                self.client_id,
                clock_skew_in_seconds=60  # Allow 60 seconds clock skew
            )

            # Verify the issuer
            if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                raise ValueError('Wrong issuer.')

            return idinfo

        except ValueError as e:
            raise ValidationError(f'Invalid ID token: {str(e)}')
    
    def get_user_info_from_token(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from Google using access token.
        """
        response = requests.get(
            'https://www.googleapis.com/oauth2/v2/userinfo',
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if response.status_code != 200:
            raise ValidationError('Failed to get user info from Google')
        
        return response.json()
    
    def authenticate_or_create_user(self, user_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Authenticate existing user or create new user from Google OAuth.
        """
        email = user_info.get('email')
        if not email:
            raise ValidationError('Email not provided by Google')
        
        # Check if user exists
        user = user_get_by_email(email=email)
        
        if user:
            # User exists, authenticate
            if not user.is_active:
                raise ValidationError('Account is inactive')
        else:
            # Create new user
            user_data = {
                'email': email,
                'first_name': user_info.get('given_name', ''),
                'last_name': user_info.get('family_name', ''),
                'is_verified': user_info.get('email_verified', False),
                'avatar': user_info.get('picture', ''),
            }
            
            user = user_create(**user_data)
        
        # Create tokens
        tokens = create_tokens_for_user(user=user)
        
        return {
            'user_id': str(user.id),
            'email': user.email,
            'tokens': tokens,
            'is_new_user': user.date_joined.date() == user.last_login_at.date() if user.last_login_at else True
        }


def google_oauth_login(*, code: str, **kwargs) -> Dict[str, Any]:
    """
    Handle Google OAuth login flow.
    """
    oauth_service = GoogleOAuthService()
    
    # Exchange code for tokens
    token_data = oauth_service.exchange_code_for_token(code)
    
    # Verify ID token and get user info
    if token_data.get('id_token'):
        user_info = oauth_service.verify_id_token(token_data['id_token'])
    else:
        # Fallback to access token
        user_info = oauth_service.get_user_info_from_token(token_data['access_token'])
    
    # Authenticate or create user
    return oauth_service.authenticate_or_create_user(user_info)


def google_oauth_get_auth_url(*, state: Optional[str] = None) -> str:
    """
    Get Google OAuth authorization URL.
    """
    oauth_service = GoogleOAuthService()
    return oauth_service.get_authorization_url(state=state)
