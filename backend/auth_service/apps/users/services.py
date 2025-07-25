"""
User services for auth_service project.
"""
from typing import Optional, Dict, Any
from django.db import transaction
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.common.utils import model_update

User = get_user_model()


@transaction.atomic
def user_create(
    *,
    email: str,
    password: Optional[str] = None,
    first_name: str = '',
    last_name: str = '',
    is_active: bool = True,
    is_staff: bool = False,
    role: str = User.UserRole.USER,
    **extra_fields
) -> User:
    """
    Create a new user.
    """
    user = User.objects.create_user(
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        is_active=is_active,
        is_staff=is_staff,
        role=role,
        **extra_fields
    )
    return user


@transaction.atomic
def user_update(*, user: User, data: Dict[str, Any]) -> User:
    """
    Update user information.
    """
    non_side_effect_fields = [
        'first_name',
        'last_name',
        'phone_number',
        'date_of_birth',
        'avatar',
    ]
    
    user, has_updated = model_update(
        instance=user,
        fields=non_side_effect_fields,
        data=data
    )
    
    return user


@transaction.atomic
def user_change_password(*, user: User, old_password: str, new_password: str) -> User:
    """
    Change user password.
    """
    if not user.check_password(old_password):
        raise ValidationError('Invalid old password')
    
    user.set_password(new_password)
    user.password_changed_at = timezone.now()
    user.save(update_fields=['password', 'password_changed_at'])
    
    # Invalidate all JWT tokens
    user.invalidate_jwt_tokens()
    
    return user


@transaction.atomic
def user_reset_password(*, user: User, new_password: str) -> User:
    """
    Reset user password (admin action or forgot password).
    """
    user.set_password(new_password)
    user.password_changed_at = timezone.now()
    user.save(update_fields=['password', 'password_changed_at'])
    
    # Invalidate all JWT tokens
    user.invalidate_jwt_tokens()
    
    return user


@transaction.atomic
def user_activate(*, user: User) -> User:
    """
    Activate user account.
    """
    user.is_active = True
    user.save(update_fields=['is_active'])
    return user


@transaction.atomic
def user_deactivate(*, user: User) -> User:
    """
    Deactivate user account.
    """
    user.is_active = False
    user.save(update_fields=['is_active'])
    
    # Invalidate all JWT tokens
    user.invalidate_jwt_tokens()
    
    return user


@transaction.atomic
def user_verify_email(*, user: User) -> User:
    """
    Verify user email.
    """
    user.is_verified = True
    user.save(update_fields=['is_verified'])
    return user


@transaction.atomic
def user_profile_update(*, user: User, data: Dict[str, Any]) -> User:
    """
    Update user profile information.
    """
    profile = user.profile
    
    profile_fields = [
        'bio',
        'location',
        'website',
        'twitter_url',
        'linkedin_url',
        'github_url',
        'timezone',
        'language',
        'email_notifications',
        'push_notifications',
    ]
    
    profile, has_updated = model_update(
        instance=profile,
        fields=profile_fields,
        data=data
    )
    
    return user
