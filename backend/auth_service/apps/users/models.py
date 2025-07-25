"""
User models for auth_service project.
"""
import uuid
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.contrib.auth.models import BaseUserManager as DjangoBaseUserManager
from django.db import models
from django.core.validators import EmailValidator

from apps.common.models import BaseModel


class UserManager(DjangoBaseUserManager):
    """
    Custom user manager for User model.
    """
    
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and return a regular user with an email and password.
        """
        if not email:
            raise ValueError('The Email field must be set')
        
        email = self.normalize_email(email.lower())
        user = self.model(email=email, **extra_fields)
        
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        
        user.full_clean()
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with an email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class User(BaseModel, AbstractBaseUser, PermissionsMixin):
    """
    Custom user model with email as the unique identifier.
    """
    
    class UserRole(models.TextChoices):
        ADMIN = 'admin', 'Admin'
        USER = 'user', 'User'
    
    email = models.EmailField(
        unique=True,
        validators=[EmailValidator()],
        help_text='Required. Enter a valid email address.'
    )
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    
    role = models.CharField(
        max_length=10,
        choices=UserRole.choices,
        default=UserRole.USER
    )
    
    # JWT key for token invalidation
    jwt_key = models.UUIDField(default=uuid.uuid4)
    
    # Profile fields
    phone_number = models.CharField(max_length=20, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    avatar = models.URLField(blank=True)
    
    # Timestamps
    last_login_at = models.DateTimeField(null=True, blank=True)
    password_changed_at = models.DateTimeField(null=True, blank=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_active']),
            models.Index(fields=['role']),
        ]
    
    def __str__(self):
        return self.email
    
    @property
    def full_name(self):
        """Return the user's full name."""
        return f"{self.first_name} {self.last_name}".strip()
    
    @property
    def is_admin(self):
        """Check if user is admin."""
        return self.role == self.UserRole.ADMIN or self.is_superuser
    
    def get_jwt_secret_key(self):
        """Get JWT secret key for this user."""
        return str(self.jwt_key)
    
    def invalidate_jwt_tokens(self):
        """Invalidate all JWT tokens for this user."""
        self.jwt_key = uuid.uuid4()
        self.save(update_fields=['jwt_key'])


class UserProfile(BaseModel):
    """
    Extended user profile information.
    """
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        related_name='profile'
    )
    bio = models.TextField(max_length=500, blank=True)
    location = models.CharField(max_length=100, blank=True)
    website = models.URLField(blank=True)
    
    # Social media links
    twitter_url = models.URLField(blank=True)
    linkedin_url = models.URLField(blank=True)
    github_url = models.URLField(blank=True)
    
    # Preferences
    timezone = models.CharField(max_length=50, default='UTC')
    language = models.CharField(max_length=10, default='en')
    
    # Notifications
    email_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def __str__(self):
        return f"{self.user.email}'s profile"
