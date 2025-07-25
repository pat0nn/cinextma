"""
Local development settings for auth_service project.
"""
from .base import *
from .jwt import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']

# Database for local development
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST'),
        'PORT': env('DB_PORT', default='5432'),
        'OPTIONS': {
            'sslmode': 'disable',
        },
    }
}

# CORS settings for local development
CORS_ALLOW_ALL_ORIGINS = True
CORS_ALLOW_CREDENTIALS = True

# Email backend for local development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Cache for local development
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
    }
}

# Logging for local development
LOGGING['loggers']['auth_service']['level'] = 'DEBUG'
LOGGING['root']['level'] = 'DEBUG'

# Django Extensions (if installed)
try:
    import django_extensions
    INSTALLED_APPS += ['django_extensions']
except ImportError:
    pass

# Django Debug Toolbar (disabled for now)
# try:
#     import debug_toolbar
#     INSTALLED_APPS += ['debug_toolbar']
#     MIDDLEWARE = ['debug_toolbar.middleware.DebugToolbarMiddleware'] + MIDDLEWARE
#     INTERNAL_IPS = ['127.0.0.1']
# except ImportError:
#     pass
