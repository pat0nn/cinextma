"""
User selectors for auth_service project.
"""
from typing import Optional, Dict, Any
from django.contrib.auth import get_user_model
from django.db.models import QuerySet
from django.db import models

from apps.common.utils import get_object

User = get_user_model()


def user_get_login_data(*, user: User) -> Dict[str, Any]:
    """
    Get user login data for API response.
    """
    return {
        'id': str(user.id),
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'full_name': user.full_name,
        'is_active': user.is_active,
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser,
        'is_verified': user.is_verified,
        'role': user.role,
        'avatar': user.avatar,
        'last_login_at': user.last_login_at,
        'created_at': user.created_at,
    }


def user_get_profile_data(*, user: User) -> Dict[str, Any]:
    """
    Get user profile data for API response.
    """
    profile = user.profile
    return {
        'id': str(user.id),
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'full_name': user.full_name,
        'phone_number': user.phone_number,
        'date_of_birth': user.date_of_birth,
        'avatar': user.avatar,
        'is_verified': user.is_verified,
        'role': user.role,
        'profile': {
            'bio': profile.bio,
            'location': profile.location,
            'website': profile.website,
            'twitter_url': profile.twitter_url,
            'linkedin_url': profile.linkedin_url,
            'github_url': profile.github_url,
            'timezone': profile.timezone,
            'language': profile.language,
            'email_notifications': profile.email_notifications,
            'push_notifications': profile.push_notifications,
        },
        'created_at': user.created_at,
        'updated_at': user.updated_at,
    }


def user_list(*, filters: Optional[Dict[str, Any]] = None) -> QuerySet[User]:
    """
    Get list of users with optional filters.
    """
    filters = filters or {}
    qs = User.objects.select_related('profile').all()
    
    # Apply filters
    if 'is_active' in filters:
        qs = qs.filter(is_active=filters['is_active'])
    
    if 'is_verified' in filters:
        qs = qs.filter(is_verified=filters['is_verified'])
    
    if 'role' in filters:
        qs = qs.filter(role=filters['role'])
    
    if 'search' in filters:
        search_term = filters['search']
        qs = qs.filter(
            models.Q(email__icontains=search_term) |
            models.Q(first_name__icontains=search_term) |
            models.Q(last_name__icontains=search_term)
        )
    
    return qs


def user_get(*, user_id: str) -> Optional[User]:
    """
    Get user by ID.
    """
    return get_object(User, id=user_id)


def user_get_by_email(*, email: str) -> Optional[User]:
    """
    Get user by email.
    """
    return get_object(User, email=email)
