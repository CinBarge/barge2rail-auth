import logging

from oauth2_provider.contrib.oidc.claims import ScopeClaims

from .models import ApplicationRole, UserAppRole

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("django.security")


class CustomScopeClaims(ScopeClaims):
    """Add application-specific roles to OIDC claims.

    SECURITY FIX: Only exposes roles for the REQUESTING application.
    Previously leaked all application roles to any requesting app.

    Phase 5 (Dec 2025): Added feature-level permissions support.
    JWT now includes both legacy 'role' and new 'permissions' structure
    for backward compatibility during transition period.

    JWT claim format:
    {
        "application_roles": {
            "primetrade": {
                "role": "Office",           # Legacy role (backward compat)
                "permissions": ["read", "write"],  # Legacy permissions
                "features": {               # NEW: Feature-level permissions
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

    def _get_rbac_permissions(self, user, application):
        """Get permissions from new RBAC system (UserAppRole).

        Returns:
            dict or None: Feature permissions dict, or None if no RBAC role assigned.

        Example return:
            {
                "bol": ["view", "create", "modify"],
                "releases": ["view"],
            }
        """
        try:
            user_app_role = (
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
            return user_app_role.get_permissions()
        except UserAppRole.DoesNotExist:
            return None
        except UserAppRole.MultipleObjectsReturned:
            # If multiple roles exist (e.g., different tenants), get first active one
            user_app_role = (
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
            if user_app_role:
                return user_app_role.get_permissions()
            return None

    def scope_profile(self):
        """Override profile scope to include application roles.

        SECURITY FIX: Only include role for the requesting application.

        Includes both legacy role and new feature permissions for backward
        compatibility during RBAC transition.
        """
        logger.debug("[OIDC CLAIMS] scope_profile() called")

        # Get standard profile claims from parent
        claims = super().scope_profile()
        logger.debug(f"[OIDC CLAIMS] Standard profile claims: {list(claims.keys())}")

        user = self.user
        requesting_app = self._get_requesting_application()

        logger.debug(
            f"[OIDC CLAIMS] User: {user.email if user else 'None'}, "
            f"Requesting app: {requesting_app}"
        )

        # SECURITY FIX: Only return roles for the requesting application
        roles = {}

        if requesting_app:
            # Try legacy ApplicationRole first (backward compatibility)
            app_roles = ApplicationRole.objects.filter(
                user=user, application=requesting_app
            ).only("application", "role", "permissions")

            for ar in app_roles:
                role_data = {
                    "role": ar.role,
                    "permissions": ar.permissions or [],
                }

                # NEW: Add feature-level permissions from RBAC system
                feature_perms = self._get_rbac_permissions(user, requesting_app)
                if feature_perms:
                    role_data["features"] = feature_perms
                    logger.debug(
                        f"[OIDC CLAIMS] Added RBAC features for {ar.application.slug}: "
                        f"{list(feature_perms.keys())}"
                    )

                roles[ar.application.slug] = role_data
                logger.debug(f"[OIDC CLAIMS] Added {ar.application.slug}: {ar.role}")
        else:
            # Fallback: if no requesting app context, return empty roles
            # This prevents leaking roles when app context is unknown
            security_logger.warning(
                f"[OIDC CLAIMS] No requesting app context for user {user.email}. "
                "Returning empty application_roles."
            )

        claims["application_roles"] = roles
        logger.debug(f"[OIDC CLAIMS] Returning claims with keys: {list(claims.keys())}")
        return claims

    def scope_roles(self):
        """Custom roles scope.

        SECURITY FIX: Only include role for the requesting application.

        Includes both legacy role and new feature permissions for backward
        compatibility during RBAC transition.
        """
        logger.debug("[OIDC CLAIMS] scope_roles() called")

        user = self.user
        requesting_app = self._get_requesting_application()

        roles = {}

        if requesting_app:
            # Try legacy ApplicationRole first (backward compatibility)
            app_roles = ApplicationRole.objects.filter(
                user=user, application=requesting_app
            ).only("application", "role", "permissions")

            for ar in app_roles:
                role_data = {
                    "role": ar.role,
                    "permissions": ar.permissions or [],
                }

                # NEW: Add feature-level permissions from RBAC system
                feature_perms = self._get_rbac_permissions(user, requesting_app)
                if feature_perms:
                    role_data["features"] = feature_perms

                roles[ar.application.slug] = role_data
        else:
            security_logger.warning(
                f"[OIDC CLAIMS] No requesting app context for user {user.email} "
                "in scope_roles. Returning empty application_roles."
            )

        return {"application_roles": roles}
