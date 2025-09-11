from django.urls import path
from . import views, auth_views

app_name = 'sso'

urlpatterns = [
    # Enhanced authentication endpoints
    path('login/email/', auth_views.login_email, name='login_email'),
    path('login/google/', auth_views.login_google, name='login_google'),
    path('login/anonymous/', auth_views.login_anonymous, name='login_anonymous'),
    path('register/email/', auth_views.register_email, name='register_email'),
    
    # Legacy authentication endpoints (keep for backward compatibility)
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('refresh/', views.refresh_token, name='refresh_token'),
    path('validate/', views.validate_token, name='validate_token'),
    path('profile/', views.profile, name='profile'),
    
    # Application management
    path('applications/', views.ApplicationListCreateView.as_view(), name='application-list'),
    path('applications/<uuid:pk>/', views.ApplicationDetailView.as_view(), name='application-detail'),
    
    # User role management
    path('roles/', views.UserRoleListCreateView.as_view(), name='role-list'),
    path('roles/<uuid:pk>/', views.UserRoleDetailView.as_view(), name='role-detail'),
]