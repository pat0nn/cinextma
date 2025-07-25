"""
Authentication views for auth_service project.
"""
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.exceptions import ValidationError

from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    RefreshTokenSerializer,
    PasswordResetRequestSerializer,
    PasswordResetSerializer,
    EmailVerificationSerializer,
    ChangePasswordSerializer,
    UserSerializer,
    GoogleOAuthSerializer,
    GoogleOAuthUrlSerializer,
)
from .services import (
    auth_register,
    auth_login,
    auth_logout,
    auth_refresh_token,
    auth_send_password_reset_email,
    auth_reset_password,
    auth_send_verification_email,
    auth_verify_email,
)
from .oauth import google_oauth_login, google_oauth_get_auth_url
from apps.users.services import user_change_password
from apps.users.selectors import user_get_login_data


def get_client_info(request):
    """Extract client information from request."""
    return {
        'ip_address': request.META.get('REMOTE_ADDR'),
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
    }


class RegisterView(APIView):
    """
    User registration endpoint.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            result = auth_register(**serializer.validated_data)
            return Response(result, status=status.HTTP_201_CREATED)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class LoginView(APIView):
    """
    User login endpoint.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        client_info = get_client_info(request)
        
        try:
            result = auth_login(
                **serializer.validated_data,
                **client_info
            )
            return Response(result, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class LogoutView(APIView):
    """
    User logout endpoint.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # Get access token from request
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        access_token = ''
        if auth_header.startswith('Bearer '):
            access_token = auth_header[7:]
        
        try:
            result = auth_logout(
                user=request.user,
                access_token=access_token
            )
            return Response(result, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class RefreshTokenView(APIView):
    """
    Token refresh endpoint.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = RefreshTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            result = auth_refresh_token(**serializer.validated_data)
            return Response(result, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class MeView(APIView):
    """
    Get current user information.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        data = user_get_login_data(user=request.user)
        return Response(data, status=status.HTTP_200_OK)
    
    def put(self, request):
        serializer = UserSerializer(
            request.user,
            data=request.data,
            partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        data = user_get_login_data(user=request.user)
        return Response(data, status=status.HTTP_200_OK)


class PasswordResetRequestView(APIView):
    """
    Password reset request endpoint.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        result = auth_send_password_reset_email(**serializer.validated_data)
        return Response(result, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    """
    Password reset endpoint.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            result = auth_reset_password(**serializer.validated_data)
            return Response(result, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class ChangePasswordView(APIView):
    """
    Change password endpoint.
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            user_change_password(
                user=request.user,
                **serializer.validated_data
            )
            return Response(
                {'message': 'Password changed successfully'},
                status=status.HTTP_200_OK
            )
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class EmailVerificationView(APIView):
    """
    Email verification endpoint.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        try:
            result = auth_verify_email(**serializer.validated_data)
            return Response(result, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class ResendVerificationView(APIView):
    """
    Resend email verification endpoint.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.is_verified:
            return Response(
                {'message': 'Email is already verified'},
                status=status.HTTP_400_BAD_REQUEST
            )

        result = auth_send_verification_email(user=request.user)
        return Response(result, status=status.HTTP_200_OK)


class GoogleOAuthUrlView(APIView):
    """
    Get Google OAuth authorization URL.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = GoogleOAuthUrlSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        auth_url = google_oauth_get_auth_url(
            state=serializer.validated_data.get('state')
        )

        return Response({
            'auth_url': auth_url
        }, status=status.HTTP_200_OK)


class GoogleOAuthCallbackView(APIView):
    """
    Handle Google OAuth callback.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = GoogleOAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        client_info = get_client_info(request)

        try:
            result = google_oauth_login(
                **serializer.validated_data,
                **client_info
            )
            return Response(result, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
