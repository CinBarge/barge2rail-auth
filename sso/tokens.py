"""
Custom JWT token classes with additional claims.

UPDATED Dec 2025: Uses UserAppRole (RBAC system) instead of deprecated ApplicationRole.
"""

import logging

from rest_framework_simplejwt.tokens import RefreshToken as BaseRefreshToken

logger = logging.getLogger(__name__)


class CustomRefreshToken(BaseRefreshToken):
    """
    Custom refresh token that includes additional user claims.

    Uses UserAppRole (RBAC system) for application_roles claim.
    Provides backward compatibility with legacy format while adding
    new RBAC features dict.
    """

    @classmethod
    def for_user(cls, user):
        """
        Generate token with custom claims for user.

        application_roles format:
        {
            "app_slug": {
                "role": "Admin",           # legacy_role for backward compat
                "permissions": ["full_access"],  # Legacy array format
                "features": {              # NEW: Feature-level RBAC
                    "dashboard": ["view", "create", "modify"],
                    ...
                }
            }
        }
        """
        token = super().for_user(user)

        # Add custom claims
        token["email"] = user.email if user.email else ""
        token["is_sso_admin"] = user.is_sso_admin
        token["auth_type"] = user.auth_type
        token["is_anonymous"] = user.is_anonymous
        token["display_name"] = user.display_name

        # Add application roles using UserAppRole (RBAC system)
        application_roles = {}
        try:
            # Import here to avoid circular imports
            from sso.models import UserAppRole

            user_app_roles = UserAppRole.objects.select_related(
                "role", "role__application"
            ).filter(user=user, is_active=True)

            for uar in user_app_roles:
                app_slug = uar.role.application.slug
                role = uar.role

                # Get legacy permissions array for backward compat
                # Admin gets full_access, others get basic read/write
                if role.legacy_role and role.legacy_role.lower() == "admin":
                    legacy_permissions = ["full_access"]
                else:
                    legacy_permissions = ["read"]

                application_roles[app_slug] = {
                    # Use legacy_role for backward compat
                    "role": role.legacy_role or role.name,
                    # Legacy permissions array for backward compat
                    "permissions": legacy_permissions,
                    # NEW: Feature-level permissions from RBAC
                    "features": uar.get_permissions(),
                }

            logger.debug(
                f"[TOKENS] Built application_roles for {user.email}: "
                f"{list(application_roles.keys())}"
            )

        except Exception as e:
            logger.error(f"[TOKENS] Error building application_roles: {e}")
            # Fall back to empty dict on error
            application_roles = {}

        token["application_roles"] = application_roles

        return token
