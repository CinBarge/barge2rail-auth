from django.urls import path
from . import views, auth_views, oauth_views

urlpatterns = [
    # ==========================================
    # WEB-BASED AUTHENTICATION (Browser Users)
    # ==========================================

    # NEW: Web login form
    path('web/login/', views.login_web, name='login_web'),
    path('logout/', views.logout, name='logout'),

    # Google OAuth (office staff)
    path('admin/google/login/', views.admin_google_login, name='admin_google_login'),
    path('admin/google/callback/', views.admin_google_callback, name='admin_google_callback'),

    # OAuth frontend flow (popup/redirect)
    path('oauth/google/url/', views.google_oauth_url, name='google_oauth_url'),
    path('google/callback/', views.login_google_oauth, name='google_oauth_api_callback'),
    path('session/<uuid:session_id>/tokens/', views.exchange_session_for_tokens, name='exchange_session_for_tokens'),

    # ==========================================
    # API ENDPOINTS (Programmatic Access)
    # ==========================================

    # NEW: API authentication
    path('api/login/', views.login_api, name='login_api'),
    path('api/register/', views.register_email, name='register_api'),

    # OAuth 2.0 Provider (SSO acts as IdP)
    path('authorize/', oauth_views.oauth_authorize, name='oauth_authorize'),
    path('token/', oauth_views.oauth_token, name='oauth_token'),

    # Token management
    path('refresh/', views.refresh_token, name='refresh_token'),
    path('validate/', views.validate_token, name='validate_token'),

    # Enhanced authentication endpoints
    path('login/email/', views.login_email, name='login_email'),
    path('login/anonymous/', views.login_anonymous, name='login_anonymous'),
    path('register/email/', views.register_email, name='register_email'),

    # ==========================================
    # COMMON ENDPOINTS
    # ==========================================

    path('me/', views.user_profile, name='user_profile'),
    path('status/', views.auth_status, name='auth_status'),
    path('verify/', views.verify_access, name='verify_access'),
    path('health/', views.health_check, name='health_check'),
    path('config/google/', views.google_config_check, name='google_config_check'),

    # ==========================================
    # LEGACY ENDPOINTS (Backward Compatibility)
    # ==========================================

    # DEPRECATED: Use /auth/api/login/ instead
    path('login/', views.login_api, name='login_legacy'),
    path('register/', views.register, name='register_legacy'),
    path('profile/', views.user_profile, name='profile'),

    # ==========================================
    # ADMIN ENDPOINTS
    # ==========================================

    path('applications/', views.ApplicationListCreateView.as_view(), name='application-list'),
    path('applications/<uuid:pk>/', views.ApplicationDetailView.as_view(), name='application-detail'),
    path('roles/', views.UserRoleListCreateView.as_view(), name='role-list'),
    path('roles/<uuid:pk>/', views.UserRoleDetailView.as_view(), name='role-detail'),
]
