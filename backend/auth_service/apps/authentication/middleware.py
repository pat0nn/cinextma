"""
Custom middleware for authentication.
"""
import time
import logging
from django.http import JsonResponse
from django.core.cache import cache
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class RateLimitMiddleware(MiddlewareMixin):
    """
    Rate limiting middleware to prevent abuse.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """
        Check rate limits for incoming requests.
        """
        # Skip rate limiting for certain paths
        skip_paths = ['/api/health/', '/admin/']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        # Get client IP
        ip_address = self.get_client_ip(request)
        
        # Different limits for different endpoints
        if request.path.startswith('/api/auth/login/'):
            return self.check_rate_limit(ip_address, 'login', 5, 300)  # 5 attempts per 5 minutes
        elif request.path.startswith('/api/auth/register/'):
            return self.check_rate_limit(ip_address, 'register', 3, 3600)  # 3 attempts per hour
        elif request.path.startswith('/api/auth/password/reset/'):
            return self.check_rate_limit(ip_address, 'password_reset', 3, 3600)  # 3 attempts per hour
        else:
            return self.check_rate_limit(ip_address, 'general', 100, 3600)  # 100 requests per hour
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def check_rate_limit(self, ip_address, action, limit, window):
        """Check if request exceeds rate limit."""
        cache_key = f"rate_limit:{action}:{ip_address}"
        
        try:
            current_requests = cache.get(cache_key, 0)
            
            if current_requests >= limit:
                logger.warning(f"Rate limit exceeded for {ip_address} on {action}")
                return JsonResponse({
                    'error': 'Rate limit exceeded. Please try again later.',
                    'retry_after': window
                }, status=429)
            
            # Increment counter
            cache.set(cache_key, current_requests + 1, window)
            
        except Exception as e:
            logger.error(f"Rate limiting error: {e}")
            # If cache fails, allow the request to proceed
            pass
        
        return None


class RequestLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log API requests for monitoring and debugging.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)
    
    def process_request(self, request):
        """Log incoming request."""
        request.start_time = time.time()
        
        # Log request details
        logger.info(f"Request: {request.method} {request.path} from {self.get_client_ip(request)}")
        
        return None
    
    def process_response(self, request, response):
        """Log response details."""
        if hasattr(request, 'start_time'):
            duration = time.time() - request.start_time
            
            logger.info(
                f"Response: {request.method} {request.path} "
                f"Status: {response.status_code} "
                f"Duration: {duration:.3f}s"
            )
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Middleware to add security headers to responses.
    """
    
    def process_response(self, request, response):
        """Add security headers."""
        # Prevent clickjacking
        response['X-Frame-Options'] = 'DENY'
        
        # Prevent MIME type sniffing
        response['X-Content-Type-Options'] = 'nosniff'
        
        # XSS protection
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Referrer policy
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Content Security Policy (basic)
        response['Content-Security-Policy'] = "default-src 'self'"
        
        return response


class CORSMiddleware(MiddlewareMixin):
    """
    Custom CORS middleware for microservice communication.
    """
    
    def process_response(self, request, response):
        """Add CORS headers."""
        # Allow specific origins for microservice communication
        allowed_origins = getattr(settings, 'MICROSERVICE_ALLOWED_ORIGINS', [])
        origin = request.META.get('HTTP_ORIGIN')
        
        if origin in allowed_origins:
            response['Access-Control-Allow-Origin'] = origin
        
        response['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response['Access-Control-Allow-Headers'] = (
            'Accept, Accept-Language, Content-Language, Content-Type, '
            'Authorization, X-Requested-With'
        )
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Max-Age'] = '86400'
        
        return response
    
    def process_request(self, request):
        """Handle preflight requests."""
        if request.method == 'OPTIONS':
            response = JsonResponse({})
            return self.process_response(request, response)
        
        return None
