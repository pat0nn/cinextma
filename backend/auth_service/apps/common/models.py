"""
Common models for auth_service project.
"""
import uuid
from django.db import models


class BaseModel(models.Model):
    """
    Base model with common fields for all models.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class TimestampedModel(models.Model):
    """
    Abstract model with timestamp fields.
    """
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
