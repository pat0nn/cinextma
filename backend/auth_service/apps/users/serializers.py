"""
Serializers for users app.
"""
from rest_framework import serializers
from django.contrib.auth import get_user_model

from .models import UserProfile

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model.
    """
    full_name = serializers.ReadOnlyField()
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone_number', 'date_of_birth', 'avatar',
            'is_active', 'is_staff', 'is_superuser', 'is_verified',
            'role', 'last_login_at', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'email', 'is_active', 'is_staff', 'is_superuser', 
            'is_verified', 'role', 'last_login_at', 'created_at', 'updated_at'
        ]


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for UserProfile model.
    """
    
    class Meta:
        model = UserProfile
        fields = [
            'bio', 'location', 'website', 'twitter_url', 'linkedin_url',
            'github_url', 'timezone', 'language', 'email_notifications',
            'push_notifications'
        ]


class UserDetailSerializer(serializers.ModelSerializer):
    """
    Detailed serializer for User model with profile.
    """
    full_name = serializers.ReadOnlyField()
    profile = UserProfileSerializer(read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'first_name', 'last_name', 'full_name',
            'phone_number', 'date_of_birth', 'avatar',
            'is_active', 'is_staff', 'is_superuser', 'is_verified',
            'role', 'last_login_at', 'created_at', 'updated_at', 'profile'
        ]
        read_only_fields = [
            'id', 'email', 'is_active', 'is_staff', 'is_superuser', 
            'is_verified', 'role', 'last_login_at', 'created_at', 'updated_at'
        ]
