from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.http import HttpResponse
from django.urls import include, path

from core.views import Health, SecureEcho  # add
from sso.admin_oauth_views import admin_oauth_callback, admin_oauth_login
from sso.views import google_auth_callback


def sentry_test_error(request):
    """
    Temporary test endpoint - DELETE after Sentry verification.
    Triggers a ZeroDivisionError to test Sentry integration.
    """
    1 / 0  # noqa: B018
    return HttpResponse("This line will never execute")


urlpatterns = [
    path("admin/", admin.site.urls),
    # Admin OAuth URLs (Phase 4) - must come before general auth includes
    path("sso/admin/oauth/login/", admin_oauth_login, name="admin_oauth_login"),
    path(
        "sso/admin/oauth/callback/", admin_oauth_callback, name="admin_oauth_callback"
    ),
    # Google callback MUST come before includes to take precedence
    path("auth/google/callback/", google_auth_callback, name="google_oauth_callback"),
    # OAuth2 Provider endpoints (django-oauth-toolkit)
    # Provides: /o/authorize/, /o/token/, /o/revoke_token/, /o/introspect/
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
    # MCP Server endpoint (mcp_server.urls provides /mcp path)
    path("", include("mcp_server.urls")),
    path("api/auth/", include(("sso.urls", "sso"), namespace="sso")),
    path("auth/", include("sso.urls")),  # Also include under /auth/ for admin OAuth
    path("health/", Health.as_view()),  # add
    path("secure/", SecureEcho.as_view()),  # add
    # TEMPORARY: Remove after Sentry verification
    path("sentry-test/", sentry_test_error, name="sentry_test"),
    path("", include("dashboard.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
