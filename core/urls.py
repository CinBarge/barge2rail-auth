from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from core.views import Health, SecureEcho  # add
from sso.admin_oauth_views import admin_oauth_callback, admin_oauth_login
from sso.admin_views import (
    assignment_delete,
    assignment_edit,
    assignment_list,
    bulk_assign_role,
    clone_role,
    compare_roles,
    effective_permissions,
    export_roles,
    feature_create,
    feature_delete,
    feature_edit,
    feature_list,
    import_roles,
    permission_search,
    rbac_dashboard,
    role_create,
    role_delete,
    role_edit,
    role_history,
    role_list,
    role_permission_matrix,
)
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
    path(
        "admin/sso/role/<int:role_id>/history/",
        role_history,
        name="sso_role_history",
    ),
    # RBAC management views
    path("admin/sso/rbac/", rbac_dashboard, name="sso_rbac_dashboard"),
    path(
        "admin/sso/rbac/effective-permissions/",
        effective_permissions,
        name="sso_effective_permissions",
    ),
    path(
        "admin/sso/rbac/compare-roles/",
        compare_roles,
        name="sso_compare_roles",
    ),
    path(
        "admin/sso/rbac/bulk-assign/",
        bulk_assign_role,
        name="sso_bulk_assign_role",
    ),
    path(
        "admin/sso/rbac/permission-search/",
        permission_search,
        name="sso_permission_search",
    ),
    path(
        "admin/sso/rbac/export/",
        export_roles,
        name="sso_export_roles",
    ),
    path(
        "admin/sso/rbac/export/<int:app_id>/",
        export_roles,
        name="sso_export_roles_app",
    ),
    path(
        "admin/sso/rbac/import/",
        import_roles,
        name="sso_import_roles",
    ),
    # Feature management (RBAC Dashboard v2)
    path(
        "admin/sso/rbac/features/",
        feature_list,
        name="sso_feature_list",
    ),
    path(
        "admin/sso/rbac/features/add/",
        feature_create,
        name="sso_feature_create",
    ),
    path(
        "admin/sso/rbac/features/<int:feature_id>/edit/",
        feature_edit,
        name="sso_feature_edit",
    ),
    path(
        "admin/sso/rbac/features/<int:feature_id>/delete/",
        feature_delete,
        name="sso_feature_delete",
    ),
    # Role management (RBAC Dashboard v2)
    path(
        "admin/sso/rbac/roles/",
        role_list,
        name="sso_role_list",
    ),
    path(
        "admin/sso/rbac/roles/add/",
        role_create,
        name="sso_role_create",
    ),
    path(
        "admin/sso/rbac/roles/<int:role_id>/edit/",
        role_edit,
        name="sso_role_edit",
    ),
    path(
        "admin/sso/rbac/roles/<int:role_id>/delete/",
        role_delete,
        name="sso_role_delete",
    ),
    # Assignment management (RBAC Dashboard v2)
    path(
        "admin/sso/rbac/assignments/",
        assignment_list,
        name="sso_assignment_list",
    ),
    path(
        "admin/sso/rbac/assignments/<int:assignment_id>/edit/",
        assignment_edit,
        name="sso_assignment_edit",
    ),
    path(
        "admin/sso/rbac/assignments/<int:assignment_id>/delete/",
        assignment_delete,
        name="sso_assignment_delete",
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
