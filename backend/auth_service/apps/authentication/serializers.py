"""
Serializers for authentication app.
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.core.validators import EmailValidator

User = get_user_model()


class RegisterSerializer(serializers.Serializer):
    """
    Serializer for user registration.
    """
    email = serializers.EmailField(validators=[EmailValidator()])
    password = serializers.CharField(min_length=8, write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    first_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    last_name = serializers.CharField(max_length=150, required=False, allow_blank=True)
    
    def validate_email(self, value):
        """Validate email is unique."""
        if User.objects.filter(email=value.lower()).exists():
            raise serializers.ValidationError('User with this email already exists.')
        return value.lower()
    
    def validate(self, attrs):
        """Validate password confirmation."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError('Passwords do not match.')
        attrs.pop('password_confirm')
        return attrs


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    device_id = serializers.CharField(required=False, allow_blank=True)
    device_name = serializers.CharField(required=False, allow_blank=True)


class RefreshTokenSerializer(serializers.Serializer):
    """
    Serializer for token refresh.
    """
    refresh_token = serializers.CharField()


class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for password reset request.
    """
    email = serializers.EmailField()


class PasswordResetSerializer(serializers.Serializer):
    """
    Serializer for password reset.
    """
    token = serializers.CharField()
    new_password = serializers.CharField(min_length=8, write_only=True)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password confirmation."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError('Passwords do not match.')
        attrs.pop('new_password_confirm')
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    """
    Serializer for email verification.
    """
    token = serializers.CharField()


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change.
    """
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(min_length=8, write_only=True)
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password confirmation."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError('Passwords do not match.')
        attrs.pop('new_password_confirm')
        return attrs


class GoogleOAuthSerializer(serializers.Serializer):
    """
    Serializer for Google OAuth authentication.
    """
    code = serializers.CharField()
    state = serializers.CharField(required=False, allow_blank=True)


class GoogleOAuthUrlSerializer(serializers.Serializer):
    """
    Serializer for Google OAuth URL request.
    """
    state = serializers.CharField(required=False, allow_blank=True)


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for user data.
    """
    full_name = serializers.ReadOnlyField()

    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'is_active', 'is_staff', 'is_superuser', 'is_verified',
            'role', 'avatar', 'phone_number', 'date_of_birth',
            'last_login_at', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'is_active', 'is_staff', 'is_superuser', 'is_verified',
            'last_login_at', 'created_at', 'updated_at'
        ]
