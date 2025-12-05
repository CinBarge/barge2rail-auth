from django.urls import path

from . import admin_oauth_views, auth_views, jwks_views, password_views, views
from .password_reset_views import (
    CustomPasswordResetCompleteView,
    CustomPasswordResetConfirmView,
    CustomPasswordResetDoneView,
    CustomPasswordResetView,
)

app_name = "sso"

urlpatterns = [
    # Admin Google OAuth - OAuth Admin Integration (Phase 4)
    path(
        "admin/oauth/login/",
        admin_oauth_views.admin_oauth_login,
        name="admin_oauth_login",
    ),
    path(
        "admin/oauth/callback/",
        admin_oauth_views.admin_oauth_callback,
        name="admin_oauth_callback",
    ),
    # MAIN Google OAuth - For general user authentication
    path("login/google/", auth_views.login_google, name="login_google"),
    path(
        "google/callback/", auth_views.google_auth_callback, name="google_auth_callback"
    ),
    # Email Authentication
    path("login/email/", auth_views.login_email, name="login_email"),
    path("register/email/", auth_views.register_email, name="register_email"),
    # Anonymous Authentication
    path("login/anonymous/", auth_views.login_anonymous, name="login_anonymous"),
    path("change-pin/", auth_views.change_pin, name="change_pin"),
    # Token Management
    path("refresh/", views.refresh_token, name="refresh_token"),
    path("validate/", views.validate_token, name="validate_token"),
    # Secure token exchange (for OAuth callbacks - never expose tokens in URLs)
    path(
        "exchange/<uuid:session_id>/",
        views.exchange_session_for_tokens,
        name="exchange_session_for_tokens",
    ),
    # User Profile
    path("me/", views.profile_page, name="profile_page"),
    path("profile/", views.user_profile, name="user_profile"),  # API endpoint
    path("verify/", views.verify_access, name="verify_access"),
    path("health/", views.health_check, name="health_check"),
    path("config/google/", views.google_config_check, name="google_config_check"),
    # Core Authentication
    path("register/", views.register, name="register"),
    path("login/", views.login_web, name="login"),
    path("logout/", views.logout, name="logout"),
    # Debug
    path("debug/google/", auth_views.debug_google_config, name="debug_google_config"),
    # Password Management (Phase 1)
    path("change-password/", password_views.change_password, name="change_password"),
    path("forgot-password/", password_views.forgot_password, name="forgot_password"),
    # Django standard password_reset URLs (for template compatibility)
    path("password/reset/", password_views.forgot_password, name="password_reset"),
    path(
        "password/reset/complete/",
        password_views.password_reset_complete,
        name="password_reset_complete",
    ),
    path(
        "reset-password/<str:token>/",
        password_views.reset_password,
        name="reset_password",
    ),
    # Password Reset (Django built-in)
    path("password/reset/", CustomPasswordResetView.as_view(), name="password_reset"),
    path(
        "password/reset/sent/",
        CustomPasswordResetDoneView.as_view(),
        name="password_reset_sent",
    ),
    path(
        "password/reset/<uidb64>/<token>/",
        CustomPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path(
        "password/reset/done/",
        CustomPasswordResetCompleteView.as_view(),
        name="password_reset_done",
    ),
    # JWKS endpoint for JWT signature verification
    path(".well-known/jwks.json", jwks_views.jwks_endpoint, name="jwks"),
]
