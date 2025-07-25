# 🔧 Auth Service Troubleshooting & Best Practices

## 🚨 Common Issues & Solutions

### 1. Token-Related Issues

**❌ Problem: "Invalid token" errors**
```
Error: HTTP 401 - Invalid token
```

**✅ Solutions:**
```python
# Check token format
def debug_token_issue(token):
    print(f"Token length: {len(token)}")
    print(f"Token starts with: {token[:20]}...")
    
    # Decode without verification to see payload
    import jwt
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        print(f"Token payload: {payload}")
        print(f"Token expired: {payload.get('exp', 0) < time.time()}")
    except Exception as e:
        print(f"Token decode error: {e}")

# Common fixes:
# 1. Check token expiration
# 2. Verify JWT secret key matches
# 3. Ensure token is not blacklisted
# 4. Check token format (Bearer prefix)
```

**❌ Problem: Token refresh fails**
```
Error: HTTP 400 - Invalid refresh token
```

**✅ Solutions:**
```python
# Check refresh token in database
def debug_refresh_token(refresh_token):
    from apps.authentication.models import RefreshToken
    
    try:
        token_obj = RefreshToken.objects.get(token=refresh_token)
        print(f"Token exists: True")
        print(f"Is blacklisted: {token_obj.is_blacklisted}")
        print(f"Expires at: {token_obj.expires_at}")
        print(f"Is valid: {token_obj.is_valid}")
    except RefreshToken.DoesNotExist:
        print("Refresh token not found in database")

# Common fixes:
# 1. Check if refresh token exists in database
# 2. Verify token is not blacklisted
# 3. Check expiration time
# 4. Ensure token rotation is handled correctly
```

### 2. Database Issues

**❌ Problem: Migration errors**
```
django.db.utils.ProgrammingError: relation "users" does not exist
```

**✅ Solutions:**
```bash
# Reset migrations (development only)
python manage.py migrate users zero
python manage.py migrate authentication zero
python manage.py migrate core zero
python manage.py migrate common zero

# Recreate migrations
python manage.py makemigrations common
python manage.py makemigrations users
python manage.py makemigrations authentication
python manage.py makemigrations core

# Apply migrations
python manage.py migrate
```

**❌ Problem: Database connection errors**
```
django.db.utils.OperationalError: could not connect to server
```

**✅ Solutions:**
```python
# Check database settings
def test_db_connection():
    from django.db import connection
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            print("Database connection: OK")
    except Exception as e:
        print(f"Database connection failed: {e}")

# Common fixes:
# 1. Check DATABASE_URL or DB_* environment variables
# 2. Ensure PostgreSQL is running
# 3. Verify database credentials
# 4. Check network connectivity
```

### 3. Google OAuth Issues

**❌ Problem: OAuth redirect URI mismatch**
```
Error: redirect_uri_mismatch
```

**✅ Solutions:**
```python
# Check OAuth configuration
def debug_oauth_config():
    from django.conf import settings
    
    print(f"Client ID: {settings.GOOGLE_OAUTH_CLIENT_ID}")
    print(f"Redirect URI: {settings.GOOGLE_OAUTH_REDIRECT_URI}")
    
    # Verify in Google Cloud Console:
    # 1. OAuth 2.0 Client IDs
    # 2. Authorized redirect URIs
    # 3. Must match exactly (including http/https)
```

**❌ Problem: Invalid OAuth credentials**
```
Error: invalid_client
```

**✅ Solutions:**
```bash
# Check environment variables
echo "GOOGLE_OAUTH_CLIENT_ID: $GOOGLE_OAUTH_CLIENT_ID"
echo "GOOGLE_OAUTH_CLIENT_SECRET: $GOOGLE_OAUTH_CLIENT_SECRET"

# Verify in Google Cloud Console:
# 1. Enable Google+ API or Google Identity API
# 2. Create OAuth 2.0 credentials
# 3. Copy correct Client ID and Secret
```

### 4. Microservice Communication Issues

**❌ Problem: Service-to-service authentication fails**
```
Error: HTTP 401 - Invalid microservice key
```

**✅ Solutions:**
```python
# Debug microservice authentication
def debug_microservice_auth(request):
    microservice_key = request.META.get('HTTP_X_MICROSERVICE_KEY')
    expected_key = settings.MICROSERVICE_SECRET_KEY
    
    print(f"Received key: {microservice_key}")
    print(f"Expected key: {expected_key}")
    print(f"Keys match: {microservice_key == expected_key}")

# Common fixes:
# 1. Ensure MICROSERVICE_SECRET_KEY is set
# 2. Use correct header name: X-Microservice-Key
# 3. Verify key matches across all services
```

**❌ Problem: Service discovery issues**
```
Error: Connection refused to auth-service:8000
```

**✅ Solutions:**
```bash
# Check Docker network
docker network ls
docker network inspect auth_service_default

# Test service connectivity
docker exec user-service ping auth-service
docker exec user-service curl http://auth-service:8000/api/health/

# Common fixes:
# 1. Ensure services are on same Docker network
# 2. Use service names as hostnames
# 3. Check port mappings
# 4. Verify service startup order
```

## 📊 Performance Optimization

### 1. Database Optimization

**Query Optimization:**
```python
# Optimize user queries
class OptimizedUserViewSet(viewsets.ModelViewSet):
    def get_queryset(self):
        return User.objects.select_related('profile').prefetch_related(
            'refresh_tokens',
            'blacklisted_tokens'
        )

# Add database indexes
class Migration(migrations.Migration):
    operations = [
        migrations.RunSQL(
            "CREATE INDEX CONCURRENTLY idx_refresh_tokens_user_active "
            "ON refresh_tokens (user_id) WHERE NOT is_blacklisted;"
        ),
        migrations.RunSQL(
            "CREATE INDEX CONCURRENTLY idx_blacklisted_tokens_token "
            "ON blacklisted_tokens USING hash (token);"
        ),
    ]
```

**Connection Pooling:**
```python
# settings/production.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('DB_NAME'),
        'USER': env('DB_USER'),
        'PASSWORD': env('DB_PASSWORD'),
        'HOST': env('DB_HOST'),
        'PORT': env('DB_PORT'),
        'OPTIONS': {
            'MAX_CONNS': 20,
            'MIN_CONNS': 5,
        },
        'CONN_MAX_AGE': 600,
    }
}
```

### 2. Caching Strategy

**Redis Caching:**
```python
# Cache user data for token validation
from django.core.cache import cache
import hashlib

def get_cached_user(user_id):
    cache_key = f"user:{user_id}"
    user_data = cache.get(cache_key)
    
    if not user_data:
        user = User.objects.select_related('profile').get(id=user_id)
        user_data = {
            'id': str(user.id),
            'email': user.email,
            'is_active': user.is_active,
            'role': user.role,
            'jwt_key': str(user.jwt_key)
        }
        cache.set(cache_key, user_data, timeout=300)  # 5 minutes
    
    return user_data

# Cache token blacklist
def is_token_blacklisted(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    cache_key = f"blacklist:{token_hash}"
    
    is_blacklisted = cache.get(cache_key)
    if is_blacklisted is None:
        is_blacklisted = BlacklistedToken.objects.filter(token=token).exists()
        cache.set(cache_key, is_blacklisted, timeout=3600)  # 1 hour
    
    return is_blacklisted
```

### 3. Rate Limiting

**Advanced Rate Limiting:**
```python
# Custom rate limiting
from django.core.cache import cache
import time

class SmartRateLimitMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        if not self.check_rate_limit(request):
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'retry_after': 60
            }, status=429)
        
        return self.get_response(request)
    
    def check_rate_limit(self, request):
        ip = self.get_client_ip(request)
        user_id = getattr(request, 'user', {}).get('id')
        
        # Different limits for authenticated vs anonymous
        if user_id:
            limit_key = f"rate_limit:user:{user_id}"
            limit = 1000  # 1000 requests per hour for authenticated users
        else:
            limit_key = f"rate_limit:ip:{ip}"
            limit = 100   # 100 requests per hour for anonymous users
        
        current_time = int(time.time() // 3600)  # Hour bucket
        cache_key = f"{limit_key}:{current_time}"
        
        current_count = cache.get(cache_key, 0)
        if current_count >= limit:
            return False
        
        cache.set(cache_key, current_count + 1, timeout=3600)
        return True
```

## 🔒 Security Best Practices

### 1. Token Security

**Secure Token Storage:**
```python
# Rotate JWT keys periodically
def rotate_user_jwt_key(user):
    user.jwt_key = uuid.uuid4()
    user.save(update_fields=['jwt_key'])
    
    # Invalidate all existing tokens
    BlacklistedToken.objects.filter(user=user).delete()

# Implement token binding
def bind_token_to_device(token, request):
    device_fingerprint = hashlib.sha256(
        f"{request.META.get('HTTP_USER_AGENT', '')}"
        f"{request.META.get('HTTP_ACCEPT_LANGUAGE', '')}"
        f"{request.META.get('HTTP_ACCEPT_ENCODING', '')}"
        .encode()
    ).hexdigest()
    
    # Store fingerprint with token
    cache.set(f"token_device:{token}", device_fingerprint, timeout=3600)
```

### 2. Input Validation

**Comprehensive Validation:**
```python
# Custom validators
from django.core.exceptions import ValidationError
import re

def validate_strong_password(password):
    if len(password) < 8:
        raise ValidationError('Password must be at least 8 characters long')
    
    if not re.search(r'[A-Z]', password):
        raise ValidationError('Password must contain uppercase letter')
    
    if not re.search(r'[a-z]', password):
        raise ValidationError('Password must contain lowercase letter')
    
    if not re.search(r'\d', password):
        raise ValidationError('Password must contain number')
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise ValidationError('Password must contain special character')

# Email validation
def validate_email_domain(email):
    allowed_domains = ['gmail.com', 'company.com', 'university.edu']
    domain = email.split('@')[1].lower()
    
    if domain not in allowed_domains:
        raise ValidationError(f'Email domain {domain} not allowed')
```

### 3. Audit Logging

**Comprehensive Audit Trail:**
```python
# Audit logging
import logging
import json

audit_logger = logging.getLogger('auth_audit')

class AuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        start_time = time.time()
        response = self.get_response(request)
        duration = time.time() - start_time
        
        # Log sensitive operations
        if request.path.startswith('/api/auth/'):
            self.log_auth_event(request, response, duration)
        
        return response
    
    def log_auth_event(self, request, response, duration):
        user_id = getattr(request, 'user', {}).get('id', 'anonymous')
        
        audit_data = {
            'timestamp': time.time(),
            'user_id': user_id,
            'ip_address': self.get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'duration': duration,
            'request_size': len(request.body) if hasattr(request, 'body') else 0,
            'response_size': len(response.content) if hasattr(response, 'content') else 0
        }
        
        audit_logger.info(json.dumps(audit_data))
```

## 📈 Monitoring & Alerting

### 1. Health Checks

**Advanced Health Monitoring:**
```python
# Enhanced health check
from django.http import JsonResponse
from django.db import connection
from django.core.cache import cache
import requests

def advanced_health_check(request):
    health_data = {
        'service': 'auth-service',
        'status': 'healthy',
        'timestamp': timezone.now().isoformat(),
        'checks': {}
    }
    
    # Database check
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        health_data['checks']['database'] = 'healthy'
    except Exception as e:
        health_data['checks']['database'] = f'unhealthy: {str(e)}'
        health_data['status'] = 'unhealthy'
    
    # Cache check
    try:
        cache.set('health_check', 'ok', 30)
        if cache.get('health_check') == 'ok':
            health_data['checks']['cache'] = 'healthy'
        else:
            health_data['checks']['cache'] = 'unhealthy: cache not working'
            health_data['status'] = 'degraded'
    except Exception as e:
        health_data['checks']['cache'] = f'unhealthy: {str(e)}'
        health_data['status'] = 'unhealthy'
    
    # External service checks
    try:
        response = requests.get('https://www.google.com', timeout=5)
        health_data['checks']['external_connectivity'] = 'healthy'
    except Exception as e:
        health_data['checks']['external_connectivity'] = f'unhealthy: {str(e)}'
        health_data['status'] = 'degraded'
    
    status_code = 200 if health_data['status'] == 'healthy' else 503
    return JsonResponse(health_data, status=status_code)
```

### 2. Metrics Collection

**Custom Metrics:**
```python
# Metrics collection
from django.core.cache import cache
import time

class MetricsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        start_time = time.time()
        response = self.get_response(request)
        duration = time.time() - start_time
        
        # Collect metrics
        self.record_request_metrics(request, response, duration)
        
        return response
    
    def record_request_metrics(self, request, response, duration):
        timestamp = int(time.time() // 60)  # Per minute
        
        # Request count
        cache.set(
            f"metrics:requests:{timestamp}",
            cache.get(f"metrics:requests:{timestamp}", 0) + 1,
            timeout=3600
        )
        
        # Response time
        cache.set(
            f"metrics:response_time:{timestamp}",
            cache.get(f"metrics:response_time:{timestamp}", []) + [duration],
            timeout=3600
        )
        
        # Error rate
        if response.status_code >= 400:
            cache.set(
                f"metrics:errors:{timestamp}",
                cache.get(f"metrics:errors:{timestamp}", 0) + 1,
                timeout=3600
            )
```

## 🚀 Deployment Best Practices

### 1. Environment Configuration

**Production Settings:**
```python
# settings/production.py
import sentry_sdk
from sentry_sdk.integrations.django import DjangoIntegration

# Security
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'json': {
            'format': '{"level": "%(levelname)s", "time": "%(asctime)s", "module": "%(module)s", "message": "%(message)s"}',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': '/app/logs/auth_service.log',
            'maxBytes': 1024*1024*100,  # 100MB
            'backupCount': 5,
            'formatter': 'json',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
        'auth_audit': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# Sentry error tracking
sentry_sdk.init(
    dsn=env('SENTRY_DSN'),
    integrations=[DjangoIntegration()],
    traces_sample_rate=0.1,
    send_default_pii=True
)
```

### 2. Backup Strategy

**Database Backup:**
```bash
#!/bin/bash
# backup_auth_db.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/auth_service"
DB_NAME="auth_service"

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > $BACKUP_DIR/auth_db_$DATE.sql

# Compress backup
gzip $BACKUP_DIR/auth_db_$DATE.sql

# Keep only last 7 days of backups
find $BACKUP_DIR -name "auth_db_*.sql.gz" -mtime +7 -delete

echo "Backup completed: auth_db_$DATE.sql.gz"
```

Auth-service đã được thiết kế với đầy đủ các best practices để đảm bảo tính bảo mật, hiệu suất và khả năng mở rộng! 🚀
