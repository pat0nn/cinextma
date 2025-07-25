"""
URL configuration for users app.
"""
from django.urls import path

from .views import (
    UserListView,
    UserDetailView,
    UserProfileView,
)

app_name = 'users'

urlpatterns = [
    path('', UserListView.as_view(), name='user_list'),
    path('<uuid:user_id>/', UserDetailView.as_view(), name='user_detail'),
    path('<uuid:user_id>/profile/', UserProfileView.as_view(), name='user_profile'),
]
