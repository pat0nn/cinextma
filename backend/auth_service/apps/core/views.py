"""
Core views for auth_service project.
"""
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db import connection
from django.conf import settings
from django.utils import timezone


class HealthCheckView(APIView):
    """
    Health check endpoint for monitoring.
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """
        Return health status of the service.
        """
        health_data = {
            'service': 'auth-service',
            'status': 'healthy',
            'version': '1.0.0',
            'timestamp': timezone.now().isoformat(),
        }
        
        # Check database connection
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            health_data['database'] = 'connected'
        except Exception as e:
            health_data['database'] = 'disconnected'
            health_data['status'] = 'unhealthy'
            health_data['error'] = str(e)
        
        # Check cache connection (if Redis is configured)
        try:
            from django.core.cache import cache
            cache.set('health_check', 'ok', 30)
            if cache.get('health_check') == 'ok':
                health_data['cache'] = 'connected'
            else:
                health_data['cache'] = 'disconnected'
        except Exception as e:
            health_data['cache'] = 'disconnected'
        
        status_code = status.HTTP_200_OK if health_data['status'] == 'healthy' else status.HTTP_503_SERVICE_UNAVAILABLE
        
        return Response(health_data, status=status_code)
