from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from core.views import Health, SecureEcho  # add
from sso.admin_oauth_views import admin_oauth_callback, admin_oauth_login
from sso.admin_views import clone_role, role_permission_matrix
from sso.jwks_views import jwks_endpoint
from sso.views import google_auth_callback

urlpatterns = [
    # JWKS endpoint - must be at root for standard OAuth2/OIDC compliance
    path(".well-known/jwks.json", jwks_endpoint, name="jwks"),
    # Custom admin views (must come before admin.site.urls)
    path(
        "admin/sso/role/<int:role_id>/permissions/",
        role_permission_matrix,
        name="sso_role_permission_matrix",
    ),
    path(
        "admin/sso/role/<int:role_id>/clone/",
        clone_role,
        name="sso_clone_role",
    ),
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
    path("", include("dashboard.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
