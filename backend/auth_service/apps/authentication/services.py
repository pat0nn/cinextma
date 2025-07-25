"""
Authentication services for auth_service project.
"""
import secrets
import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings

from .models import (
    RefreshToken, 
    BlacklistedToken, 
    PasswordResetToken, 
    EmailVerificationToken,
    LoginAttempt
)
from .tokens import create_tokens_for_user, RefreshTokenClass, blacklist_access_token
from apps.users.services import user_create, user_reset_password, user_verify_email
from apps.users.selectors import user_get_by_email

User = get_user_model()


@transaction.atomic
def auth_register(
    *,
    email: str,
    password: str,
    first_name: str = '',
    last_name: str = '',
    **extra_fields
) -> Dict[str, Any]:
    """
    Register a new user.
    """
    # Check if user already exists
    if User.objects.filter(email=email).exists():
        raise ValidationError('User with this email already exists')
    
    # Create user
    user = user_create(
        email=email,
        password=password,
        first_name=first_name,
        last_name=last_name,
        is_active=True,
        **extra_fields
    )
    
    # Send verification email
    auth_send_verification_email(user=user)
    
    return {
        'user_id': str(user.id),
        'email': user.email,
        'message': 'User registered successfully. Please check your email for verification.'
    }


def auth_login(
    *,
    email: str,
    password: str,
    device_id: Optional[str] = None,
    device_name: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Dict[str, Any]:
    """
    Authenticate user and return tokens.
    """
    # Get user by email
    user = user_get_by_email(email=email)

    # Log login attempt
    login_attempt_data = {
        'email': email,
        'ip_address': ip_address or '',
        'user_agent': user_agent or '',
        'result': LoginAttempt.AttemptResult.FAILED
    }

    if user is None or not user.check_password(password):
        login_attempt_data['failure_reason'] = 'Invalid credentials'
        LoginAttempt.objects.create(**login_attempt_data)
        raise ValidationError('Invalid email or password')

    if not user.is_active:
        login_attempt_data['failure_reason'] = 'Account inactive'
        LoginAttempt.objects.create(**login_attempt_data)
        raise ValidationError('Account is inactive')

    # Log successful login
    login_attempt_data['result'] = LoginAttempt.AttemptResult.SUCCESS
    login_attempt_data.pop('failure_reason', None)
    LoginAttempt.objects.create(**login_attempt_data)

    # Update last login
    with transaction.atomic():
        user.last_login_at = timezone.now()
        user.save(update_fields=['last_login_at'])

    # Create tokens
    tokens = create_tokens_for_user(
        user=user,
        device_id=device_id,
        device_name=device_name,
        ip_address=ip_address,
        user_agent=user_agent
    )

    return {
        'user_id': str(user.id),
        'email': user.email,
        'tokens': tokens
    }


@transaction.atomic
def auth_logout(*, user: User, access_token: str) -> Dict[str, Any]:
    """
    Logout user and blacklist tokens.
    """
    # Blacklist access token
    blacklist_access_token(access_token)
    
    # Blacklist all refresh tokens for this user
    RefreshToken.objects.filter(user=user, is_blacklisted=False).update(
        is_blacklisted=True
    )
    
    return {'message': 'Logged out successfully'}


@transaction.atomic
def auth_refresh_token(*, refresh_token: str) -> Dict[str, Any]:
    """
    Refresh access token using refresh token.
    """
    try:
        # Validate refresh token
        token = RefreshTokenClass(token=refresh_token)
        user = token.get_user()
        
        # Check if token is valid in database
        if not token.is_valid_in_db():
            raise ValidationError('Invalid refresh token')
        
        # Blacklist old refresh token if rotation is enabled
        if settings.JWT_SETTINGS.get('ROTATE_REFRESH_TOKENS', True):
            token.blacklist_in_db()
        
        # Create new tokens
        tokens = create_tokens_for_user(user=user)
        
        return {
            'user_id': str(user.id),
            'tokens': tokens
        }
        
    except Exception:
        raise ValidationError('Invalid refresh token')


def auth_send_verification_email(*, user: User) -> Dict[str, Any]:
    """
    Send email verification token to user.
    """
    # Generate verification token
    token = secrets.token_urlsafe(32)
    expires_at = timezone.now() + timedelta(hours=24)
    
    # Save token to database
    EmailVerificationToken.objects.create(
        user=user,
        token=token,
        expires_at=expires_at
    )
    
    # Send email (implement based on your email backend)
    verification_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    
    send_mail(
        subject='Verify your email address',
        message=f'Please click the following link to verify your email: {verification_url}',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    
    return {'message': 'Verification email sent successfully'}


@transaction.atomic
def auth_verify_email(*, token: str) -> Dict[str, Any]:
    """
    Verify user email using verification token.
    """
    try:
        verification_token = EmailVerificationToken.objects.get(token=token)
        
        if not verification_token.is_valid:
            raise ValidationError('Invalid or expired verification token')
        
        # Verify user email
        user_verify_email(user=verification_token.user)
        
        # Mark token as used
        verification_token.use()
        
        return {
            'user_id': str(verification_token.user.id),
            'message': 'Email verified successfully'
        }
        
    except EmailVerificationToken.DoesNotExist:
        raise ValidationError('Invalid verification token')


def auth_send_password_reset_email(*, email: str) -> Dict[str, Any]:
    """
    Send password reset token to user email.
    """
    user = user_get_by_email(email=email)
    if not user:
        # Don't reveal if email exists or not
        return {'message': 'If the email exists, a password reset link has been sent'}
    
    # Generate reset token
    token = secrets.token_urlsafe(32)
    expires_at = timezone.now() + timedelta(hours=1)
    
    # Save token to database
    PasswordResetToken.objects.create(
        user=user,
        token=token,
        expires_at=expires_at
    )
    
    # Send email
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    
    send_mail(
        subject='Reset your password',
        message=f'Please click the following link to reset your password: {reset_url}',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    
    return {'message': 'If the email exists, a password reset link has been sent'}


@transaction.atomic
def auth_reset_password(*, token: str, new_password: str) -> Dict[str, Any]:
    """
    Reset user password using reset token.
    """
    try:
        reset_token = PasswordResetToken.objects.get(token=token)
        
        if not reset_token.is_valid:
            raise ValidationError('Invalid or expired reset token')
        
        # Reset password
        user_reset_password(user=reset_token.user, new_password=new_password)
        
        # Mark token as used
        reset_token.use()
        
        return {
            'user_id': str(reset_token.user.id),
            'message': 'Password reset successfully'
        }
        
    except PasswordResetToken.DoesNotExist:
        raise ValidationError('Invalid reset token')
