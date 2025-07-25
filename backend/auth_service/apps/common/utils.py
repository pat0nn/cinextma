"""
Common utilities for auth_service project.
"""
from typing import Optional, Any
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404


def get_object(model_class, **kwargs) -> Optional[Any]:
    """
    Get object or return None if not found.
    """
    try:
        return model_class.objects.get(**kwargs)
    except model_class.DoesNotExist:
        return None


def get_object_or_error(model_class, **kwargs) -> Any:
    """
    Get object or raise 404 error if not found.
    """
    return get_object_or_404(model_class, **kwargs)


def model_update(*, instance, fields, data):
    """
    Generic model update function.
    """
    has_updated = False
    
    for field in fields:
        if field in data:
            new_value = data[field]
            current_value = getattr(instance, field)
            
            if current_value != new_value:
                setattr(instance, field, new_value)
                has_updated = True
    
    if has_updated:
        instance.full_clean()
        instance.save(update_fields=fields)
    
    return instance, has_updated
