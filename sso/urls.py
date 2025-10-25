from django.urls import path
from . import views, auth_views, oauth_views

urlpatterns = [
    # OAuth 2.0 Authorization Server
    path('authorize/', oauth_views.authorize, name='oauth_authorize'),
    path('token/', oauth_views.token_exchange, name='oauth_token'),

    # Google OAuth
    path('login/google/', auth_views.login_google, name='login_google'),
    path('google/callback/', auth_views.google_auth_callback, name='google_auth_callback'),

    # Email Authentication
    path('login/email/', auth_views.login_email, name='login_email'),
    path('register/email/', auth_views.register_email, name='register_email'),

    # Anonymous Authentication
    path('login/anonymous/', auth_views.login_anonymous, name='login_anonymous'),

    # Token Management
    path('refresh/', views.refresh_token, name='refresh_token'),
    path('validate/', views.validate_token, name='validate_token'),

    # User Profile
    path('me/', views.user_profile, name='user_profile'),
    path('verify/', views.verify_access, name='verify_access'),
    path('health/', views.health_check, name='health_check'),
    path('config/google/', views.google_config_check, name='google_config_check'),

    # Core Authentication
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),

    # Debug
    path('debug/google/', auth_views.debug_google_config, name='debug_google_config'),
]
