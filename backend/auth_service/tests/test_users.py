"""
Tests for user endpoints.
"""
import pytest
from django.urls import reverse
from django.contrib.auth import get_user_model
from rest_framework import status

User = get_user_model()


@pytest.mark.django_db
class TestUserListView:
    """Test user list endpoint."""
    
    def test_user_list_admin_access(self, admin_client, user):
        """Test admin can access user list."""
        url = reverse('users:user_list')
        
        response = admin_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert 'results' in response.data
        assert len(response.data['results']) >= 1
    
    def test_user_list_regular_user_denied(self, authenticated_client):
        """Test regular user cannot access user list."""
        url = reverse('users:user_list')
        
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_user_list_unauthenticated_denied(self, api_client):
        """Test unauthenticated user cannot access user list."""
        url = reverse('users:user_list')
        
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
    
    def test_user_list_with_filters(self, admin_client, user):
        """Test user list with filters."""
        url = reverse('users:user_list')
        
        response = admin_client.get(url, {'is_active': 'true'})
        
        assert response.status_code == status.HTTP_200_OK
        assert 'results' in response.data


@pytest.mark.django_db
class TestUserDetailView:
    """Test user detail endpoint."""
    
    def test_user_detail_own_profile(self, authenticated_client, user):
        """Test user can access their own profile."""
        url = reverse('users:user_detail', kwargs={'user_id': user.id})
        
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == user.email
    
    def test_user_detail_other_user_denied(self, authenticated_client, admin_user):
        """Test user cannot access other user's profile."""
        url = reverse('users:user_detail', kwargs={'user_id': admin_user.id})
        
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    def test_user_detail_admin_access(self, admin_client, user):
        """Test admin can access any user's profile."""
        url = reverse('users:user_detail', kwargs={'user_id': user.id})
        
        response = admin_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == user.email
    
    def test_user_detail_not_found(self, admin_client):
        """Test user detail with non-existent user."""
        import uuid
        fake_id = uuid.uuid4()
        url = reverse('users:user_detail', kwargs={'user_id': fake_id})
        
        response = admin_client.get(url)
        
        assert response.status_code == status.HTTP_404_NOT_FOUND
    
    def test_user_detail_update_own_profile(self, authenticated_client, user):
        """Test user can update their own profile."""
        url = reverse('users:user_detail', kwargs={'user_id': user.id})
        data = {
            'first_name': 'Updated',
            'last_name': 'Name',
        }
        
        response = authenticated_client.put(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['first_name'] == 'Updated'
        assert response.data['last_name'] == 'Name'


@pytest.mark.django_db
class TestUserProfileView:
    """Test user profile endpoint."""
    
    def test_user_profile_own_profile(self, authenticated_client, user):
        """Test user can access their own profile."""
        url = reverse('users:user_profile', kwargs={'user_id': user.id})
        
        response = authenticated_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['email'] == user.email
        assert 'profile' in response.data
    
    def test_user_profile_update(self, authenticated_client, user):
        """Test user can update their profile."""
        url = reverse('users:user_profile', kwargs={'user_id': user.id})
        data = {
            'bio': 'Updated bio',
            'location': 'New Location',
        }
        
        response = authenticated_client.put(url, data)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['profile']['bio'] == 'Updated bio'
        assert response.data['profile']['location'] == 'New Location'
