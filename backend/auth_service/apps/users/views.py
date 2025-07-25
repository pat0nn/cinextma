"""
User views for auth_service project.
"""
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.exceptions import ValidationError

from .selectors import user_list, user_get, user_get_login_data, user_get_profile_data
from .services import user_update, user_profile_update
from .serializers import UserSerializer, UserProfileSerializer


class UserListView(APIView):
    """
    List users endpoint (admin only).
    """
    permission_classes = [IsAuthenticated, IsAdminUser]
    
    def get(self, request):
        filters = {
            'is_active': request.query_params.get('is_active'),
            'is_verified': request.query_params.get('is_verified'),
            'role': request.query_params.get('role'),
            'search': request.query_params.get('search'),
        }
        # Remove None values
        filters = {k: v for k, v in filters.items() if v is not None}
        
        users = user_list(filters=filters)
        
        # Simple pagination
        page_size = 20
        page = int(request.query_params.get('page', 1))
        start = (page - 1) * page_size
        end = start + page_size
        
        users_page = users[start:end]
        data = [user_get_login_data(user=user) for user in users_page]
        
        return Response({
            'results': data,
            'count': users.count(),
            'page': page,
            'page_size': page_size,
        }, status=status.HTTP_200_OK)


class UserDetailView(APIView):
    """
    User detail endpoint.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id):
        # Users can only view their own profile unless they're admin
        if str(request.user.id) != str(user_id) and not request.user.is_admin:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = user_get(user_id=user_id)
        if not user:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        data = user_get_login_data(user=user)
        return Response(data, status=status.HTTP_200_OK)
    
    def put(self, request, user_id):
        # Users can only update their own profile unless they're admin
        if str(request.user.id) != str(user_id) and not request.user.is_admin:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = user_get(user_id=user_id)
        if not user:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = UserSerializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        
        try:
            user_update(user=user, data=serializer.validated_data)
            data = user_get_login_data(user=user)
            return Response(data, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class UserProfileView(APIView):
    """
    User profile endpoint.
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id):
        # Users can only view their own profile unless they're admin
        if str(request.user.id) != str(user_id) and not request.user.is_admin:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = user_get(user_id=user_id)
        if not user:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        data = user_get_profile_data(user=user)
        return Response(data, status=status.HTTP_200_OK)
    
    def put(self, request, user_id):
        # Users can only update their own profile unless they're admin
        if str(request.user.id) != str(user_id) and not request.user.is_admin:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        user = user_get(user_id=user_id)
        if not user:
            return Response(
                {'error': 'User not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = UserProfileSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        
        try:
            user_profile_update(user=user, data=serializer.validated_data)
            data = user_get_profile_data(user=user)
            return Response(data, status=status.HTTP_200_OK)
        except ValidationError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
