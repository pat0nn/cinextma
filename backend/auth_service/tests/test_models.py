"""
Tests for models.
"""
import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

from apps.authentication.models import RefreshToken, BlacklistedToken
from apps.users.models import UserProfile

User = get_user_model()


@pytest.mark.django_db
class TestUserModel:
    """Test User model."""
    
    def test_create_user(self):
        """Test creating a regular user."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpassword123',
            first_name='Test',
            last_name='User'
        )
        
        assert user.email == 'test@example.com'
        assert user.first_name == 'Test'
        assert user.last_name == 'User'
        assert user.is_active is True
        assert user.is_staff is False
        assert user.is_superuser is False
        assert user.role == User.UserRole.USER
        assert user.check_password('testpassword123')
    
    def test_create_superuser(self):
        """Test creating a superuser."""
        user = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpassword123'
        )
        
        assert user.email == 'admin@example.com'
        assert user.is_active is True
        assert user.is_staff is True
        assert user.is_superuser is True
    
    def test_user_str_representation(self):
        """Test user string representation."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpassword123'
        )
        
        assert str(user) == 'test@example.com'
    
    def test_user_full_name(self):
        """Test user full name property."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpassword123',
            first_name='Test',
            last_name='User'
        )
        
        assert user.full_name == 'Test User'
    
    def test_user_is_admin_property(self):
        """Test user is_admin property."""
        regular_user = User.objects.create_user(
            email='user@example.com',
            password='password123'
        )
        
        admin_user = User.objects.create_user(
            email='admin@example.com',
            password='password123',
            role=User.UserRole.ADMIN
        )
        
        superuser = User.objects.create_superuser(
            email='super@example.com',
            password='password123'
        )
        
        assert regular_user.is_admin is False
        assert admin_user.is_admin is True
        assert superuser.is_admin is True
    
    def test_user_invalidate_jwt_tokens(self):
        """Test invalidating JWT tokens."""
        user = User.objects.create_user(
            email='test@example.com',
            password='testpassword123'
        )
        
        old_jwt_key = user.jwt_key
        user.invalidate_jwt_tokens()
        
        assert user.jwt_key != old_jwt_key
    
    def test_user_email_validation(self):
        """Test user email validation."""
        with pytest.raises(ValidationError):
            user = User(email='invalid-email')
            user.full_clean()


@pytest.mark.django_db
class TestUserProfileModel:
    """Test UserProfile model."""
    
    def test_user_profile_creation(self, user):
        """Test user profile is created automatically."""
        assert hasattr(user, 'profile')
        assert isinstance(user.profile, UserProfile)
    
    def test_user_profile_str_representation(self, user):
        """Test user profile string representation."""
        assert str(user.profile) == f"{user.email}'s profile"
    
    def test_user_profile_update(self, user):
        """Test updating user profile."""
        profile = user.profile
        profile.bio = 'Test bio'
        profile.location = 'Test location'
        profile.save()
        
        profile.refresh_from_db()
        assert profile.bio == 'Test bio'
        assert profile.location == 'Test location'


@pytest.mark.django_db
class TestRefreshTokenModel:
    """Test RefreshToken model."""
    
    def test_refresh_token_creation(self, user):
        """Test creating a refresh token."""
        from django.utils import timezone
        from datetime import timedelta
        
        token = RefreshToken.objects.create(
            user=user,
            token='test_token',
            expires_at=timezone.now() + timedelta(days=7)
        )
        
        assert token.user == user
        assert token.token == 'test_token'
        assert token.is_blacklisted is False
    
    def test_refresh_token_is_valid(self, user):
        """Test refresh token validity."""
        from django.utils import timezone
        from datetime import timedelta
        
        # Valid token
        valid_token = RefreshToken.objects.create(
            user=user,
            token='valid_token',
            expires_at=timezone.now() + timedelta(days=7)
        )
        
        # Expired token
        expired_token = RefreshToken.objects.create(
            user=user,
            token='expired_token',
            expires_at=timezone.now() - timedelta(days=1)
        )
        
        # Blacklisted token
        blacklisted_token = RefreshToken.objects.create(
            user=user,
            token='blacklisted_token',
            expires_at=timezone.now() + timedelta(days=7),
            is_blacklisted=True
        )
        
        assert valid_token.is_valid is True
        assert expired_token.is_valid is False
        assert blacklisted_token.is_valid is False
    
    def test_refresh_token_blacklist(self, user):
        """Test blacklisting a refresh token."""
        from django.utils import timezone
        from datetime import timedelta
        
        token = RefreshToken.objects.create(
            user=user,
            token='test_token',
            expires_at=timezone.now() + timedelta(days=7)
        )
        
        assert token.is_blacklisted is False
        
        token.blacklist()
        
        assert token.is_blacklisted is True


@pytest.mark.django_db
class TestBlacklistedTokenModel:
    """Test BlacklistedToken model."""
    
    def test_blacklisted_token_creation(self, user):
        """Test creating a blacklisted token."""
        from django.utils import timezone
        from datetime import timedelta
        
        token = BlacklistedToken.objects.create(
            user=user,
            token='blacklisted_access_token',
            expires_at=timezone.now() + timedelta(minutes=15)
        )
        
        assert token.user == user
        assert token.token == 'blacklisted_access_token'
        assert str(token) == f"BlacklistedToken for {user.email}"
