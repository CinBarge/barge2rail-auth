from django.urls import path
from . import views, auth_views, oauth_views

urlpatterns = [
    # ==========================================
    # OAuth 2.0 AUTHORIZATION SERVER
    # (For PrimeTrade and other client applications)
    # ==========================================
    path('authorize/', oauth_views.oauth_authorize, name='oauth_authorize'),
    path('token/', oauth_views.oauth_token, name='oauth_token'),

    # ==========================================
    # AUTHENTICATION - Web-Based (Browser Users)
    # ==========================================
    path('web/login/', views.login_web, name='login_web'),
    path('logout/', views.logout, name='logout'),

    # ==========================================
    # AUTHENTICATION - Google OAuth
    # ==========================================
    path('login/google/', auth_views.login_google, name='login_google'),
    path('google/callback/', views.google_auth_callback, name='google_auth_callback'),
    path('admin/google/login/', views.admin_google_login, name='admin_google_login'),
    path('admin/google/callback/', views.admin_google_callback, name='admin_google_callback'),

    # ==========================================
    # AUTHENTICATION - Email/Password
    # ==========================================
    path('login/email/', views.login_email, name='login_email'),
    path('register/email/', views.register_email, name='register_email'),

    # ==========================================
    # AUTHENTICATION - Anonymous
    # ==========================================
    path('login/anonymous/', views.login_anonymous, name='login_anonymous'),

    # ==========================================
    # TOKEN MANAGEMENT
    # ==========================================
    path('refresh/', views.refresh_token, name='refresh_token'),
    path('validate/', views.validate_token, name='validate_token'),

    # ==========================================
    # OAuth Frontend Flow (Legacy)
    # ==========================================
    path('oauth/google/url/', views.google_oauth_url, name='google_oauth_url'),
    path('session/<uuid:session_id>/tokens/', views.exchange_session_for_tokens, name='exchange_session_for_tokens'),

    # ==========================================
    # USER PROFILE & STATUS
    # ==========================================
    path('me/', views.user_profile, name='user_profile'),
    path('status/', views.auth_status, name='auth_status'),
    path('verify/', views.verify_access, name='verify_access'),
    path('health/', views.health_check, name='health_check'),
    path('config/google/', views.google_config_check, name='google_config_check'),

    # ==========================================
    # LEGACY API ENDPOINTS (Backward Compatibility)
    # ==========================================
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

    # ==========================================
    # DEBUG ENDPOINTS
    # ==========================================
    path('debug/google/', auth_views.debug_google_config, name='debug_google_config'),
]