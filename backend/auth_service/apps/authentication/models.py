"""
Authentication models for auth_service project.
"""
import uuid
from datetime import datetime, timedelta
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

from apps.common.models import BaseModel

User = get_user_model()


class RefreshToken(BaseModel):
    """
    Model to store refresh tokens.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='refresh_tokens'
    )
    token = models.TextField()
    expires_at = models.DateTimeField()
    is_blacklisted = models.BooleanField(default=False)
    
    # Device information
    device_id = models.CharField(max_length=255, blank=True)
    device_name = models.CharField(max_length=100, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        db_table = 'refresh_tokens'
        verbose_name = 'Refresh Token'
        verbose_name_plural = 'Refresh Tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'is_blacklisted']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"RefreshToken for {self.user.email}"
    
    @property
    def is_expired(self):
        """Check if token is expired."""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if token is valid (not expired and not blacklisted)."""
        return not self.is_expired and not self.is_blacklisted
    
    def blacklist(self):
        """Blacklist this token."""
        self.is_blacklisted = True
        self.save(update_fields=['is_blacklisted'])


class BlacklistedToken(BaseModel):
    """
    Model to store blacklisted access tokens.
    """
    token = models.TextField()
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='blacklisted_tokens'
    )
    blacklisted_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    
    class Meta:
        db_table = 'blacklisted_tokens'
        verbose_name = 'Blacklisted Token'
        verbose_name_plural = 'Blacklisted Tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"BlacklistedToken for {self.user.email}"


class PasswordResetToken(BaseModel):
    """
    Model to store password reset tokens.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='password_reset_tokens'
    )
    token = models.TextField()
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'password_reset_tokens'
        verbose_name = 'Password Reset Token'
        verbose_name_plural = 'Password Reset Tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'is_used']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"PasswordResetToken for {self.user.email}"
    
    @property
    def is_expired(self):
        """Check if token is expired."""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if token is valid (not expired and not used)."""
        return not self.is_expired and not self.is_used
    
    def use(self):
        """Mark token as used."""
        self.is_used = True
        self.save(update_fields=['is_used'])


class EmailVerificationToken(BaseModel):
    """
    Model to store email verification tokens.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='email_verification_tokens'
    )
    token = models.TextField()
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'email_verification_tokens'
        verbose_name = 'Email Verification Token'
        verbose_name_plural = 'Email Verification Tokens'
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['user', 'is_used']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"EmailVerificationToken for {self.user.email}"
    
    @property
    def is_expired(self):
        """Check if token is expired."""
        return timezone.now() > self.expires_at
    
    @property
    def is_valid(self):
        """Check if token is valid (not expired and not used)."""
        return not self.is_expired and not self.is_used
    
    def use(self):
        """Mark token as used."""
        self.is_used = True
        self.save(update_fields=['is_used'])


class LoginAttempt(BaseModel):
    """
    Model to track login attempts for security purposes.
    """
    
    class AttemptResult(models.TextChoices):
        SUCCESS = 'success', 'Success'
        FAILED = 'failed', 'Failed'
        BLOCKED = 'blocked', 'Blocked'
    
    email = models.EmailField()
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    result = models.CharField(
        max_length=10,
        choices=AttemptResult.choices
    )
    failure_reason = models.CharField(max_length=100, blank=True)
    
    class Meta:
        db_table = 'login_attempts'
        verbose_name = 'Login Attempt'
        verbose_name_plural = 'Login Attempts'
        indexes = [
            models.Index(fields=['email', 'created_at']),
            models.Index(fields=['ip_address', 'created_at']),
            models.Index(fields=['result']),
        ]
    
    def __str__(self):
        return f"LoginAttempt for {self.email} - {self.result}"
