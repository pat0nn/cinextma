"""
JWT token classes for authentication.
"""
import jwt
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from .models import RefreshToken, BlacklistedToken

User = get_user_model()


class TokenError(Exception):
    """Base exception for token errors."""
    pass


class TokenExpiredError(TokenError):
    """Exception raised when token is expired."""
    pass


class TokenInvalidError(TokenError):
    """Exception raised when token is invalid."""
    pass


class BaseToken:
    """
    Base class for JWT tokens.
    """
    token_type = None
    lifetime = None
    
    def __init__(self, token=None, verify=True):
        if token is None:
            # Create new token
            self.payload = self.get_payload()
            self.token = self.encode_payload(self.payload)
        else:
            # Decode existing token
            self.token = token
            if verify:
                self.payload = self.decode_token(token)
            else:
                self.payload = {}
    
    def get_payload(self):
        """Get token payload."""
        now = timezone.now()
        payload = {
            'token_type': self.token_type,
            'exp': now + self.lifetime,
            'iat': now,
            'jti': str(uuid.uuid4()),
        }
        return payload
    
    def encode_payload(self, payload):
        """Encode payload to JWT token."""
        # Convert datetime objects to timestamps
        for key, value in payload.items():
            if isinstance(value, datetime):
                payload[key] = int(value.timestamp())
        
        return jwt.encode(
            payload,
            settings.JWT_SETTINGS['SECRET_KEY'],
            algorithm=settings.JWT_SETTINGS['ALGORITHM']
        )
    
    def decode_token(self, token):
        """Decode JWT token to payload."""
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SETTINGS['SECRET_KEY'],
                algorithms=[settings.JWT_SETTINGS['ALGORITHM']]
            )
            
            # Check token type
            if payload.get('token_type') != self.token_type:
                raise TokenInvalidError('Invalid token type')
            
            # Convert timestamps back to datetime objects
            for key in ['exp', 'iat']:
                if key in payload:
                    payload[key] = datetime.fromtimestamp(payload[key], tz=dt_timezone.utc)
            
            # Check if token is expired
            if payload.get('exp') and timezone.now() > payload['exp']:
                raise TokenExpiredError('Token has expired')
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError('Token has expired')
        except jwt.InvalidTokenError:
            raise TokenInvalidError('Invalid token')
    
    def __str__(self):
        return self.token


class AccessToken(BaseToken):
    """
    Access token for API authentication.
    """
    token_type = 'access'
    lifetime = settings.JWT_SETTINGS['ACCESS_TOKEN_LIFETIME']
    
    def __init__(self, user=None, token=None, verify=True):
        self.user = user
        super().__init__(token, verify)
    
    def get_payload(self):
        """Get access token payload."""
        payload = super().get_payload()
        if self.user:
            payload.update({
                'user_id': str(self.user.id),
                'email': self.user.email,
                'is_staff': self.user.is_staff,
                'is_superuser': self.user.is_superuser,
            })
        return payload
    
    def get_user(self):
        """Get user from token payload."""
        if not hasattr(self, '_user'):
            user_id = self.payload.get('user_id')
            if user_id:
                try:
                    self._user = User.objects.get(id=user_id)
                except User.DoesNotExist:
                    raise TokenInvalidError('User not found')
            else:
                self._user = None
        return self._user
    
    def is_blacklisted(self):
        """Check if token is blacklisted."""
        return BlacklistedToken.objects.filter(token=self.token).exists()


class RefreshTokenClass(BaseToken):
    """
    Refresh token for obtaining new access tokens.
    """
    token_type = 'refresh'
    lifetime = settings.JWT_SETTINGS['REFRESH_TOKEN_LIFETIME']
    
    def __init__(self, user=None, token=None, verify=True):
        self.user = user
        super().__init__(token, verify)
    
    def get_payload(self):
        """Get refresh token payload."""
        payload = super().get_payload()
        if self.user:
            payload.update({
                'user_id': str(self.user.id),
                'email': self.user.email,
            })
        return payload
    
    def get_user(self):
        """Get user from token payload."""
        if not hasattr(self, '_user'):
            user_id = self.payload.get('user_id')
            if user_id:
                try:
                    self._user = User.objects.get(id=user_id)
                except User.DoesNotExist:
                    raise TokenInvalidError('User not found')
            else:
                self._user = None
        return self._user
    
    def save_to_db(self, device_id=None, device_name=None, ip_address=None, user_agent=None):
        """Save refresh token to database."""
        if not self.user:
            raise ValueError('User is required to save refresh token')

        # Get expiration time - it should be a datetime object from get_payload
        expires_at = self.payload['exp']
        if not isinstance(expires_at, datetime):
            # If it's a timestamp, convert it
            expires_at = datetime.fromtimestamp(expires_at, tz=dt_timezone.utc)

        refresh_token = RefreshToken.objects.create(
            user=self.user,
            token=self.token,
            expires_at=expires_at,
            device_id=device_id or '',
            device_name=device_name or '',
            ip_address=ip_address,
            user_agent=user_agent or '',
        )
        return refresh_token
    
    def is_valid_in_db(self):
        """Check if refresh token is valid in database."""
        try:
            refresh_token = RefreshToken.objects.get(token=self.token)
            return refresh_token.is_valid
        except RefreshToken.DoesNotExist:
            return False
    
    def blacklist_in_db(self):
        """Blacklist refresh token in database."""
        try:
            refresh_token = RefreshToken.objects.get(token=self.token)
            refresh_token.blacklist()
        except RefreshToken.DoesNotExist:
            pass


def create_tokens_for_user(user, device_id=None, device_name=None, ip_address=None, user_agent=None):
    """
    Create access and refresh tokens for a user.
    """
    access_token = AccessToken(user=user)
    refresh_token = RefreshTokenClass(user=user)
    
    # Save refresh token to database
    refresh_token.save_to_db(
        device_id=device_id,
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    # Get expiration times
    access_exp = access_token.payload['exp']
    refresh_exp = refresh_token.payload['exp']

    # Convert to ISO format if they are datetime objects
    if isinstance(access_exp, datetime):
        access_exp = access_exp.isoformat()
    else:
        access_exp = datetime.fromtimestamp(access_exp, tz=dt_timezone.utc).isoformat()

    if isinstance(refresh_exp, datetime):
        refresh_exp = refresh_exp.isoformat()
    else:
        refresh_exp = datetime.fromtimestamp(refresh_exp, tz=dt_timezone.utc).isoformat()

    return {
        'access_token': str(access_token),
        'refresh_token': str(refresh_token),
        'access_token_expires_at': access_exp,
        'refresh_token_expires_at': refresh_exp,
    }


def blacklist_access_token(token):
    """
    Blacklist an access token.
    """
    try:
        access_token = AccessToken(token=token)
        user = access_token.get_user()
        
        BlacklistedToken.objects.create(
            token=token,
            user=user,
            expires_at=access_token.payload['exp']
        )
    except (TokenError, User.DoesNotExist):
        pass  # Token is already invalid
