"""
OIDC Claims for SSO.

Provides application roles and feature permissions in JWT claims.

DEPRECATION (Dec 2025): ApplicationRole is fully deprecated.
UserAppRole (RBAC system) is now the only source of truth.
Run `python manage.py migrate_roles` to migrate legacy entries.
"""

import logging

from oauth2_provider.contrib.oidc.claims import ScopeClaims

from .models import UserAppRole

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("django.security")


class CustomScopeClaims(ScopeClaims):
    """Add application-specific roles to OIDC claims.

    SECURITY FIX: Only exposes roles for the REQUESTING application.
    Previously leaked all application roles to any requesting app.

    RBAC (Dec 2025): UserAppRole is the only source of truth.
    ApplicationRole is fully deprecated.

    JWT claim format:
    {
        "application_roles": {
            "primetrade": {
                "role": "Admin",  # Uses legacy_role for backward compat
                "permissions": [],
                "features": {
                    "bol": ["view", "create", "modify"],
                    "releases": ["view", "create"],
                    ...
                }
            }
        }
    }
    """

    def _get_requesting_application(self):
        """Get the application making this token request."""
        # The token/request context contains the application
        if hasattr(self, "request") and self.request:
            # OAuth2 token request includes client_id
            if hasattr(self.request, "client"):
                return self.request.client
        return None

    def _get_user_app_role(self, user, application):
        """Get UserAppRole for user and application.

        Returns:
            UserAppRole or None: The user's RBAC role assignment, or None if not found.
        """
        try:
            return (
                UserAppRole.objects.select_related("role")
                .prefetch_related(
                    "role__feature_permissions__feature",
                    "role__feature_permissions__permission",
                )
                .get(
                    user=user,
                    role__application=application,
                    is_active=True,
                )
            )
        except UserAppRole.DoesNotExist:
            logger.debug(
                f"[OIDC CLAIMS] No UserAppRole found for user={user.email}, "
                f"app={application.slug}"
            )
            return None
        except UserAppRole.MultipleObjectsReturned:
            # If multiple roles exist (e.g., different tenants), use first active one
            logger.debug(
                f"[OIDC CLAIMS] Multiple UserAppRoles found for user={user.email}, "
                f"app={application.slug}, using first"
            )
            return (
                UserAppRole.objects.select_related("role")
                .prefetch_related(
                    "role__feature_permissions__feature",
                    "role__feature_permissions__permission",
                )
                .filter(
                    user=user,
                    role__application=application,
                    is_active=True,
                )
                .first()
            )

    def scope_profile(self):
        """Override profile scope to include application roles.

        SECURITY FIX: Only include role for the requesting application.
        Uses UserAppRole (RBAC system) exclusively.
        """
        logger.debug("[OIDC CLAIMS] scope_profile() called")

        # Get standard profile claims from parent
        claims = super().scope_profile()

        user = self.user
        requesting_app = self._get_requesting_application()

        logger.debug(
            f"[OIDC CLAIMS] User: {user.email if user else 'None'}, "
            f"Requesting app: {requesting_app}"
        )

        # SECURITY FIX: Only return roles for the requesting application
        roles = {}

        if requesting_app:
            user_app_role = self._get_user_app_role(user, requesting_app)

            if user_app_role:
                role = user_app_role.role
                role_data = {
                    # legacy_role for compat (apps expect "Admin" not full name)
                    "role": role.legacy_role or role.name,
                    "permissions": [],  # Legacy field, kept for compatibility
                    "features": user_app_role.get_permissions(),
                }
                roles[requesting_app.slug] = role_data
                logger.debug(
                    f"[OIDC CLAIMS] Added role for {requesting_app.slug}: "
                    f"{role.code}"
                )
            else:
                logger.debug(
                    f"[OIDC CLAIMS] No role found for user={user.email}, "
                    f"app={requesting_app.slug}"
                )
        else:
            # No requesting app context - return empty roles
            security_logger.warning(
                f"[OIDC CLAIMS] No requesting app context for user {user.email}. "
                "Returning empty application_roles."
            )

        claims["application_roles"] = roles
        return claims

    def scope_roles(self):
        """Custom roles scope.

        SECURITY FIX: Only include role for the requesting application.
        Uses UserAppRole (RBAC system) exclusively.
        """
        logger.debug("[OIDC CLAIMS] scope_roles() called")

        user = self.user
        requesting_app = self._get_requesting_application()

        roles = {}

        if requesting_app:
            user_app_role = self._get_user_app_role(user, requesting_app)

            if user_app_role:
                role = user_app_role.role
                role_data = {
                    # legacy_role for compat (apps expect "Admin" not full name)
                    "role": role.legacy_role or role.name,
                    "permissions": [],  # Legacy field, kept for compatibility
                    "features": user_app_role.get_permissions(),
                }
                roles[requesting_app.slug] = role_data
                logger.debug(
                    f"[OIDC CLAIMS] scope_roles: Added role for "
                    f"{requesting_app.slug}: {role.code}"
                )
        else:
            security_logger.warning(
                f"[OIDC CLAIMS] No requesting app context for user {user.email} "
                "in scope_roles. Returning empty application_roles."
            )

        return {"application_roles": roles}
