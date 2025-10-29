from oauth2_provider.contrib.oidc.claims import ScopeClaims

from .models import ApplicationRole


class CustomScopeClaims(ScopeClaims):
    """Add application-specific roles to OIDC claims.

    Exposes roles via the custom 'roles' scope.
    """

    def scope_roles(self):
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
