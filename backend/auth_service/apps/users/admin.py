"""
Admin configuration for users app.
"""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth import get_user_model

from .models import UserProfile

User = get_user_model()


class UserProfileInline(admin.StackedInline):
    """Inline admin for user profile."""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin configuration for User model."""
    
    inlines = (UserProfileInline,)
    
    list_display = (
        'email', 'first_name', 'last_name', 'role',
        'is_active', 'is_verified', 'is_staff', 'created_at'
    )
    
    list_filter = (
        'is_active', 'is_verified', 'is_staff', 'is_superuser',
        'role', 'created_at'
    )
    
    search_fields = ('email', 'first_name', 'last_name')
    
    ordering = ('-created_at',)
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': (
            'first_name', 'last_name', 'phone_number',
            'date_of_birth', 'avatar'
        )}),
        ('Permissions', {'fields': (
            'is_active', 'is_verified', 'is_staff', 'is_superuser',
            'role', 'groups', 'user_permissions'
        )}),
        ('Important dates', {'fields': (
            'last_login_at', 'password_changed_at', 'created_at', 'updated_at'
        )}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'password1', 'password2', 'first_name',
                'last_name', 'is_active', 'is_staff', 'role'
            ),
        }),
    )
    
    readonly_fields = (
        'created_at', 'updated_at', 'last_login_at', 'password_changed_at'
    )
    
    # Remove username field
    username = None
    
    # Use email as the username field
    USERNAME_FIELD = 'email'
