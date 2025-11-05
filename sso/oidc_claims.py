import logging

from oauth2_provider.contrib.oidc.claims import ScopeClaims

from .models import ApplicationRole

logger = logging.getLogger(__name__)


class CustomScopeClaims(ScopeClaims):
    """Add application-specific roles to OIDC claims.

    Exposes roles via the 'profile' scope (overriding standard behavior).
    """

    def scope_profile(self):
        """Override profile scope to include application roles."""
        logger.error("[OIDC CLAIMS 1] scope_profile() called")

        # Get standard profile claims from parent
        claims = super().scope_profile()
        logger.error(f"[OIDC CLAIMS 2] Standard profile claims: {list(claims.keys())}")

        # Add application roles
        user = self.user
        logger.error(f"[OIDC CLAIMS 3] User: {user.email if user else 'None'}")

        app_roles = ApplicationRole.objects.filter(user=user).only(
            "application", "role", "permissions"
        )
        logger.error(f"[OIDC CLAIMS 4] Found {app_roles.count()} ApplicationRole records")

        roles = {}
        for ar in app_roles:
            roles[ar.application] = {
                "role": ar.role,
                "permissions": ar.permissions or [],
            }
            logger.error(f"[OIDC CLAIMS 5] Added {ar.application}: {ar.role}")

        claims["application_roles"] = roles
        logger.error(f"[OIDC CLAIMS 6] Returning claims with keys: {list(claims.keys())}")
        return claims

    def scope_roles(self):
        """Custom roles scope (may not be called if not standard OIDC)."""
        logger.error("[OIDC CLAIMS 7] scope_roles() called")
        user = self.user
        app_roles = ApplicationRole.objects.filter(user=user).only(
            "application", "role", "permissions"
        )
        roles = {}
        for ar in app_roles:
            roles[ar.application] = {
                "role": ar.role,
                "permissions": ar.permissions or [],
            }
        return {"application_roles": roles}
