from django.urls import path
from . import views

urlpatterns = [
    # New enhanced endpoints following the plan
    path('login/email/', views.login_email, name='login_email'),
    path('login/anonymous/', views.login_anonymous, name='login_anonymous'),
    path('register/email/', views.register_email, name='register_email'),
    
    # Google OAuth endpoints
    path('login/google/', views.login_google_oauth, name='login_google_oauth'),
    path('oauth/google/url/', views.google_oauth_url, name='google_oauth_url'),
    path('config/google/', views.google_config_check, name='google_config_check'),
    path('google/callback/', views.google_auth_callback, name='google_auth_callback'),
    
    # Other endpoints
    path('logout/', views.logout, name='logout'),
    path('me/', views.user_profile, name='user_profile'),
    path('verify/', views.verify_access, name='verify_access'),
    path('health/', views.health_check, name='health_check'),
    path('applications/', views.applications, name='applications'),
    
    # Legacy authentication endpoints (keep for backward compatibility)
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('refresh/', views.refresh_token, name='refresh_token'),
    path('validate/', views.validate_token, name='validate_token'),
    path('profile/', views.user_profile, name='profile'),
    
    # Application management
    path('applications/', views.ApplicationListCreateView.as_view(), name='application-list'),
    path('applications/<uuid:pk>/', views.ApplicationDetailView.as_view(), name='application-detail'),
    
    # User role management
    path('roles/', views.UserRoleListCreateView.as_view(), name='role-list'),
    path('roles/<uuid:pk>/', views.UserRoleDetailView.as_view(), name='role-detail'),
]
