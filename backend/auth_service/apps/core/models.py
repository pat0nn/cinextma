"""
Core models for auth_service project.
"""
from django.db import models
from apps.common.models import BaseModel


class HealthCheck(BaseModel):
    """
    Model to store health check information.
    """
    service_name = models.CharField(max_length=100, default='auth-service')
    status = models.CharField(max_length=20, default='healthy')
    version = models.CharField(max_length=50, default='1.0.0')
    
    class Meta:
        db_table = 'health_checks'
        verbose_name = 'Health Check'
        verbose_name_plural = 'Health Checks'
    
    def __str__(self):
        return f"HealthCheck - {self.service_name} - {self.status}"
