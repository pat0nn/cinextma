"""
JWT authentication backend for DRF.
"""
from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions

from .tokens import AccessToken, TokenError, TokenExpiredError, TokenInvalidError

User = get_user_model()


class JWTAuthentication(authentication.BaseAuthentication):
    """
    JWT authentication backend for Django REST Framework.
    """
    
    def authenticate(self, request):
        """
        Authenticate user using JWT token.
        """
        header = self.get_header(request)
        if header is None:
            return None
        
        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None
        
        validated_token = self.get_validated_token(raw_token)
        user = self.get_user(validated_token)
        
        return (user, validated_token)
    
    def get_header(self, request):
        """
        Extract the header containing the JSON web token from the given request.
        """
        header = request.META.get('HTTP_AUTHORIZATION')
        
        if isinstance(header, str):
            # Work around django test client oddness
            header = header.encode('iso-8859-1')
        
        return header
    
    def get_raw_token(self, header):
        """
        Extract an unvalidated JSON web token from the given "Authorization" header value.
        """
        parts = header.split()
        
        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None
        
        if parts[0].decode('iso-8859-1') not in ('Bearer', 'JWT'):
            # Assume the header does not contain a JSON web token
            return None
        
        if len(parts) != 2:
            raise exceptions.AuthenticationFailed(
                'Authorization header must contain two space-delimited values',
                code='bad_authorization_header',
            )
        
        return parts[1]
    
    def get_validated_token(self, raw_token):
        """
        Validate an encoded JSON web token and return a validated token wrapper object.
        """
        try:
            token = AccessToken(token=raw_token.decode('iso-8859-1'))
            
            # Check if token is blacklisted
            if token.is_blacklisted():
                raise exceptions.AuthenticationFailed(
                    'Token is blacklisted',
                    code='token_blacklisted',
                )
            
            return token
            
        except TokenExpiredError:
            raise exceptions.AuthenticationFailed(
                'Token has expired',
                code='token_expired',
            )
        except TokenInvalidError:
            raise exceptions.AuthenticationFailed(
                'Invalid token',
                code='token_invalid',
            )
        except TokenError:
            raise exceptions.AuthenticationFailed(
                'Token error',
                code='token_error',
            )
    
    def get_user(self, validated_token):
        """
        Get the user associated with the validated token.
        """
        try:
            user = validated_token.get_user()
            
            if not user.is_active:
                raise exceptions.AuthenticationFailed(
                    'User is inactive',
                    code='user_inactive',
                )
            
            return user
            
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(
                'User not found',
                code='user_not_found',
            )


def default_user_authentication_rule(user):
    """
    Default rule for determining whether a user can authenticate.
    """
    return user is not None and user.is_active
