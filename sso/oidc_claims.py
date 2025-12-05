import logging

from oauth2_provider.contrib.oidc.claims import ScopeClaims

from .models import ApplicationRole

logger = logging.getLogger(__name__)
security_logger = logging.getLogger("django.security")


class CustomScopeClaims(ScopeClaims):
    """Add application-specific roles to OIDC claims.

    SECURITY FIX: Only exposes roles for the REQUESTING application.
    Previously leaked all application roles to any requesting app.
    """

    def _get_requesting_application(self):
        """Get the application making this token request."""
        # The token/request context contains the application
        if hasattr(self, "request") and self.request:
            # OAuth2 token request includes client_id
            if hasattr(self.request, "client"):
                return self.request.client
        return None

    def scope_profile(self):
        """Override profile scope to include application roles.

        SECURITY FIX: Only include role for the requesting application.
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
            # Filter to only the requesting application's roles
            app_roles = ApplicationRole.objects.filter(
                user=user, application=requesting_app
            ).only("application", "role", "permissions")

            for ar in app_roles:
                roles[ar.application.slug] = {
                    "role": ar.role,
                    "permissions": ar.permissions or [],
                }
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
        """
        logger.debug("[OIDC CLAIMS] scope_roles() called")

        user = self.user
        requesting_app = self._get_requesting_application()

        roles = {}

        if requesting_app:
            # Filter to only the requesting application's roles
            app_roles = ApplicationRole.objects.filter(
                user=user, application=requesting_app
            ).only("application", "role", "permissions")

            for ar in app_roles:
                roles[ar.application.slug] = {
                    "role": ar.role,
                    "permissions": ar.permissions or [],
                }
        else:
            security_logger.warning(
                f"[OIDC CLAIMS] No requesting app context for user {user.email} "
                "in scope_roles. Returning empty application_roles."
            )

        return {"application_roles": roles}
