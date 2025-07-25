"""
Admin configuration for authentication app.
"""
from django.contrib import admin

from .models import (
    RefreshToken,
    BlacklistedToken,
    PasswordResetToken,
    EmailVerificationToken,
    LoginAttempt,
)


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    """Admin configuration for RefreshToken model."""
    
    list_display = (
        'user', 'device_name', 'is_blacklisted',
        'expires_at', 'created_at'
    )
    
    list_filter = (
        'is_blacklisted', 'expires_at', 'created_at'
    )
    
    search_fields = ('user__email', 'device_name', 'device_id')
    
    readonly_fields = ('token', 'created_at', 'updated_at')
    
    ordering = ('-created_at',)


@admin.register(BlacklistedToken)
class BlacklistedTokenAdmin(admin.ModelAdmin):
    """Admin configuration for BlacklistedToken model."""
    
    list_display = (
        'user', 'blacklisted_at', 'expires_at'
    )
    
    list_filter = ('blacklisted_at', 'expires_at')
    
    search_fields = ('user__email',)
    
    readonly_fields = ('token', 'blacklisted_at', 'created_at', 'updated_at')
    
    ordering = ('-blacklisted_at',)


@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    """Admin configuration for PasswordResetToken model."""
    
    list_display = (
        'user', 'is_used', 'expires_at', 'created_at'
    )
    
    list_filter = ('is_used', 'expires_at', 'created_at')
    
    search_fields = ('user__email',)
    
    readonly_fields = ('token', 'created_at', 'updated_at')
    
    ordering = ('-created_at',)


@admin.register(EmailVerificationToken)
class EmailVerificationTokenAdmin(admin.ModelAdmin):
    """Admin configuration for EmailVerificationToken model."""
    
    list_display = (
        'user', 'is_used', 'expires_at', 'created_at'
    )
    
    list_filter = ('is_used', 'expires_at', 'created_at')
    
    search_fields = ('user__email',)
    
    readonly_fields = ('token', 'created_at', 'updated_at')
    
    ordering = ('-created_at',)


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """Admin configuration for LoginAttempt model."""
    
    list_display = (
        'email', 'ip_address', 'result', 'failure_reason', 'created_at'
    )
    
    list_filter = ('result', 'created_at')
    
    search_fields = ('email', 'ip_address')
    
    readonly_fields = ('created_at', 'updated_at')
    
    ordering = ('-created_at',)
