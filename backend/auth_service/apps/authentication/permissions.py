"""
Custom permissions for authentication.
"""
from rest_framework import permissions
from django.contrib.auth import get_user_model
from django.conf import settings

User = get_user_model()


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Permission to only allow owners of an object or admins to access it.
    """
    
    def has_object_permission(self, request, view, obj):
        # Admin users can access any object
        if request.user.is_admin:
            return True
        
        # Check if the object has a user attribute
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        # Check if the object is the user itself
        if isinstance(obj, User):
            return obj == request.user
        
        return False


class IsAdminUser(permissions.BasePermission):
    """
    Permission to only allow admin users.
    """
    
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_admin


class IsVerifiedUser(permissions.BasePermission):
    """
    Permission to only allow verified users.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_verified
        )


class IsActiveUser(permissions.BasePermission):
    """
    Permission to only allow active users.
    """
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_active
        )


class ReadOnlyOrOwner(permissions.BasePermission):
    """
    Permission to allow read-only access to everyone, but write access only to owners.
    """
    
    def has_permission(self, request, view):
        # Read permissions for any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return request.user and request.user.is_authenticated
        
        # Write permissions only for authenticated users
        return request.user and request.user.is_authenticated
    
    def has_object_permission(self, request, view, obj):
        # Read permissions for any authenticated user
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Write permissions only for the owner or admin
        if request.user.is_admin:
            return True
        
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        if isinstance(obj, User):
            return obj == request.user
        
        return False


class IsMicroservice(permissions.BasePermission):
    """
    Permission for microservice-to-microservice communication.
    """
    
    def has_permission(self, request, view):
        # Check for microservice authentication header
        microservice_key = request.META.get('HTTP_X_MICROSERVICE_KEY')
        expected_key = getattr(settings, 'MICROSERVICE_SECRET_KEY', None)
        
        if microservice_key and expected_key:
            return microservice_key == expected_key
        
        return False


class ThrottledPermission(permissions.BasePermission):
    """
    Permission that implements basic throttling.
    """
    
    def has_permission(self, request, view):
        # This would typically integrate with Django's throttling system
        # For now, just check if user is authenticated
        return request.user and request.user.is_authenticated


class ConditionalPermission(permissions.BasePermission):
    """
    Permission that can be configured based on view or action.
    """
    
    def has_permission(self, request, view):
        # Get permission requirements from view
        permission_config = getattr(view, 'permission_config', {})
        
        # Check different conditions based on action
        action = getattr(view, 'action', request.method.lower())
        required_permissions = permission_config.get(action, [])
        
        for permission_class in required_permissions:
            permission = permission_class()
            if not permission.has_permission(request, view):
                return False
        
        return True
