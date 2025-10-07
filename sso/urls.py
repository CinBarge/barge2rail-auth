from django.urls import path
from . import views, auth_views

urlpatterns = [
    # Primary OAuth API endpoints matching frontend expectations
    path('oauth/google/url/', views.google_oauth_url, name='google_oauth_url'),  # Match frontend: /api/auth/oauth/google/url/
    path('google/oauth-url/', views.google_oauth_url, name='google_oauth_url_alt'),  # Keep existing for compatibility
    path('google/callback/', views.login_google_oauth, name='google_oauth_api_callback'),
    path('session/<uuid:session_id>/tokens/', views.exchange_session_for_tokens, name='exchange_session_for_tokens'),
    path('status/', views.auth_status, name='auth_status'),
    path('logout/', views.logout, name='logout'),
    
    # Enhanced authentication endpoints
    path('login/email/', views.login_email, name='login_email'),
    path('login/anonymous/', views.login_anonymous, name='login_anonymous'),
    path('register/email/', views.register_email, name='register_email'),
    
    # Additional OAuth endpoints
    path('login/google/', auth_views.login_google, name='login_google'),  # For ID token (popup)
    path('login/google/oauth/', views.login_google_oauth, name='login_google_oauth'),  # For OAuth code (redirect)
    path('config/google/', views.google_config_check, name='google_config_check'),
    
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
