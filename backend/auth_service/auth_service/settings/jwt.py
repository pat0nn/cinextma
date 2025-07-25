"""
JWT settings for auth_service project.
"""
import datetime
from .base import env

# JWT Configuration
JWT_SECRET_KEY = env('JWT_SECRET_KEY', default='jwt-secret-key-change-me-in-production')
JWT_ALGORITHM = 'HS256'
JWT_ACCESS_TOKEN_LIFETIME = datetime.timedelta(minutes=env('JWT_ACCESS_TOKEN_LIFETIME_MINUTES', default=15))
JWT_REFRESH_TOKEN_LIFETIME = datetime.timedelta(days=env('JWT_REFRESH_TOKEN_LIFETIME_DAYS', default=7))

# JWT Settings
JWT_SETTINGS = {
    'SECRET_KEY': JWT_SECRET_KEY,
    'ALGORITHM': JWT_ALGORITHM,
    'ACCESS_TOKEN_LIFETIME': JWT_ACCESS_TOKEN_LIFETIME,
    'REFRESH_TOKEN_LIFETIME': JWT_REFRESH_TOKEN_LIFETIME,
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'UPDATE_LAST_LOGIN': True,
    
    # Token headers
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'apps.authentication.authentication.default_user_authentication_rule',
    
    # Token claims
    'AUTH_TOKEN_CLASSES': ('apps.authentication.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'apps.authentication.models.TokenUser',
    
    # Sliding tokens
    'SLIDING_TOKEN_REFRESH_EXP_CLAIM': 'refresh_exp',
    'SLIDING_TOKEN_LIFETIME': datetime.timedelta(minutes=5),
    'SLIDING_TOKEN_REFRESH_LIFETIME': datetime.timedelta(days=1),
}
