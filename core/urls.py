from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

from sso.views import google_auth_callback
from sso.admin_oauth_views import admin_oauth_login, admin_oauth_callback
from core.views import Health, SecureEcho  # add

urlpatterns = [
    path("admin/", admin.site.urls),
    # Admin OAuth URLs (Phase 4) - must come before general auth includes
    path("sso/admin/oauth/login/", admin_oauth_login, name="admin_oauth_login"),
    path("sso/admin/oauth/callback/", admin_oauth_callback, name="admin_oauth_callback"),
    # Google callback MUST come before includes to take precedence
    path("auth/google/callback/", google_auth_callback, name="google_oauth_callback"),

    # OAuth2 Provider endpoints (django-oauth-toolkit)
    # Provides: /o/authorize/, /o/token/, /o/revoke_token/, /o/introspect/
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),

    path("api/auth/", include("sso.urls")),
    path("auth/", include("sso.urls")),  # Also include under /auth/ for admin OAuth
    path("health/", Health.as_view()),          # add
    path("secure/", SecureEcho.as_view()),      # add
    path("", include("dashboard.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
