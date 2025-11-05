import logging

from oauth2_provider.contrib.oidc.claims import ScopeClaims

from .models import ApplicationRole

logger = logging.getLogger(__name__)


class CustomScopeClaims(ScopeClaims):
    """Add application-specific roles to OIDC claims.

    Exposes roles via the custom 'roles' scope.
    """

    def scope_roles(self):
        logger.error("[OIDC CLAIMS 1] scope_roles() called")
        user = self.user
        logger.error(f"[OIDC CLAIMS 2] User: {user.email if user else 'None'}")

        app_roles = ApplicationRole.objects.filter(user=user).only(
            "application", "role", "permissions"
        )
        logger.error(f"[OIDC CLAIMS 3] Found {app_roles.count()} ApplicationRole records")

        roles = {}
        for ar in app_roles:
            roles[ar.application] = {
                "role": ar.role,
                "permissions": ar.permissions or [],
            }
            logger.error(f"[OIDC CLAIMS 4] Added {ar.application}: {ar.role}")

        logger.error(f"[OIDC CLAIMS 5] Returning application_roles: {list(roles.keys())}")
        return {"application_roles": roles}
