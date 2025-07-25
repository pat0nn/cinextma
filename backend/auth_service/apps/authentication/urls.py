"""
URL configuration for authentication app.
"""
from django.urls import path

from .views import (
    RegisterView,
    LoginView,
    LogoutView,
    RefreshTokenView,
    MeView,
    PasswordResetRequestView,
    PasswordResetView,
    ChangePasswordView,
    EmailVerificationView,
    ResendVerificationView,
    GoogleOAuthUrlView,
    GoogleOAuthCallbackView,
)

app_name = 'authentication'

urlpatterns = [
    # Authentication endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('refresh/', RefreshTokenView.as_view(), name='refresh'),
    path('me/', MeView.as_view(), name='me'),
    
    # Password management
    path('password/reset/request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password/reset/', PasswordResetView.as_view(), name='password_reset'),
    path('password/change/', ChangePasswordView.as_view(), name='change_password'),
    
    # Email verification
    path('email/verify/', EmailVerificationView.as_view(), name='email_verify'),
    path('email/resend/', ResendVerificationView.as_view(), name='resend_verification'),

    # Google OAuth
    path('google/url/', GoogleOAuthUrlView.as_view(), name='google_oauth_url'),
    path('google/callback/', GoogleOAuthCallbackView.as_view(), name='google_oauth_callback'),
]
