"""
Custom OAuth2 Validator for B2R SSO.

This validator integrates django-oauth-toolkit with our existing
authentication and authorization infrastructure.
"""

import logging

from oauth2_provider.oauth2_validators import OAuth2Validator

from .models import Application, UserRole

logger = logging.getLogger(__name__)


class CustomOAuth2Validator(OAuth2Validator):
    """
    Custom OAuth2 validator that integrates with B2R SSO infrastructure.

    This validator:
    - Uses our custom Application model
    - Validates against existing user authentication
    - Supports role-based access control
    - Integrates with existing token management
    """

    def validate_client_id(self, client_id, request, *args, **kwargs):
        """
        Validate that the client_id exists and is active.

        Args:
            client_id: The OAuth2 client_id to validate
            request: The OAuth2 request object

        Returns:
            bool: True if client is valid and active
        """
        try:
            application = Application.objects.get(client_id=client_id, is_active=True)
            request.client = application
            logger.info(f"Client validation successful: {client_id}")
            return True
        except Application.DoesNotExist:
            logger.warning(
                f"Client validation failed: {client_id} not found or inactive"
            )
            return False

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        """
        Validate that the redirect_uri is registered for this client.

        Args:
            client_id: The OAuth2 client_id
            redirect_uri: The redirect URI to validate
            request: The OAuth2 request object

        Returns:
            bool: True if redirect_uri is valid for this client
        """
        try:
            application = Application.objects.get(client_id=client_id)

            # Parse redirect_uris (comma or newline separated)
            allowed_uris = []
            for uri in application.redirect_uris.replace("\n", ",").split(","):
                uri = uri.strip()
                if uri:
                    allowed_uris.append(uri)

            is_valid = redirect_uri in allowed_uris

            if is_valid:
                logger.info(f"Redirect URI validated for {client_id}: {redirect_uri}")
            else:
                logger.warning(f"Invalid redirect URI for {client_id}: {redirect_uri}")

            return is_valid

        except Application.DoesNotExist:
            logger.error(
                f"Application not found during redirect validation: {client_id}"
            )
            return False

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        """
        Validate that the requested scopes are allowed for this client.

        Args:
            client_id: The OAuth2 client_id
            scopes: List of requested scopes
            client: The Application object
            request: The OAuth2 request object

        Returns:
            bool: True if all scopes are valid
        """
        # Get configured scopes from settings
        from django.conf import settings

        allowed_scopes = settings.OAUTH2_PROVIDER.get("SCOPES", {}).keys()

        # Validate each requested scope
        for scope in scopes:
            if scope not in allowed_scopes:
                logger.warning(f"Invalid scope requested: {scope}")
                return False

        logger.info(f"Scopes validated for {client_id}: {scopes}")
        return True

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        """
        Store the authorization code for later exchange.

        This uses django-oauth-toolkit's default storage mechanism.
        Our custom AuthorizationCode model can co-exist for backward compatibility.
        """
        # Let the parent class handle storage using oauth2_provider models
        super().save_authorization_code(client_id, code, request, *args, **kwargs)
        logger.info(f"Authorization code saved for client: {client_id}")

    def authenticate_request(self, request):
        """
        Authenticate an OAuth2 request.

        This method integrates with Django's authentication system.
        """
        # Let parent class handle token validation
        authenticated = super().authenticate_request(request)

        if authenticated and hasattr(request, "user"):
            logger.debug(
                "Request authenticated for user: %s",
                request.user.email or request.user.username,
            )

        return authenticated

    def get_additional_claims(self, request):
        """
        Add custom claims to the ID token (for OpenID Connect).

        Includes user profile, legacy per-client role (backward compatible),
        and application-specific roles for all apps the user can access.

        Returns:
            dict: Additional claims to include in tokens
        """
        logger.error("[CLAIMS DEBUG 1] get_additional_claims() called")
        claims = {}

        if hasattr(request, "user") and request.user:
            logger.error(f"[CLAIMS DEBUG 2] User found: {request.user.email}")
            user = request.user

            # Add user profile information
            claims.update(
                {
                    "email": user.email,
                    "email_verified": bool(user.email),
                    "name": user.display_name or user.get_full_name(),
                    "preferred_username": user.username,
                }
            )

            # Add SSO admin flag (global permission across all apps)
            claims["is_sso_admin"] = user.is_sso_admin

            # Backward-compatible per-client role information (if available)
            if hasattr(request, "client") and request.client:
                try:
                    role = UserRole.objects.get(user=user, application=request.client)
                    claims["role"] = role.role
                    claims["permissions"] = role.permissions
                except UserRole.DoesNotExist:
                    pass

            # Application-specific roles (multi-app authorization)
            try:
                from .models import ApplicationRole

                app_roles = ApplicationRole.objects.filter(user=user).only(
                    "application", "role", "permissions"
                )
                logger.error(
                    f"[CLAIMS DEBUG 3] Found {app_roles.count()} ApplicationRole records"
                )
                claims["application_roles"] = {}
                for ar in app_roles:
                    # ar.application is the app slug (e.g., 'primetrade')
                    claims["application_roles"][ar.application] = {
                        "role": ar.role,
                        "permissions": ar.permissions or [],
                    }
                    logger.error(
                        f"[CLAIMS DEBUG 4] Added role for {ar.application}: {ar.role}"
                    )
                if claims.get("application_roles"):
                    apps = list(claims["application_roles"].keys())
                    logger.error(f"[CLAIMS DEBUG 5] Final application_roles: {apps}")
            except Exception as e:
                logger.error(
                    f"[CLAIMS DEBUG ERROR] Failed to build application_roles claim: {e}"
                )

        logger.error(
            f"[CLAIMS DEBUG 6] Returning claims with keys: {list(claims.keys())}"
        )
        return claims

    # DOT/OIDC compatibility: some versions call this method instead
    # of get_additional_claims when building id_token claims.
    def get_additional_id_token_claims(self, request):
        """Return additional ID token claims (delegates to get_additional_claims)."""
        return self.get_additional_claims(request)

    def validate_bearer_token(self, token, scopes, request):
        """
        Validate a bearer token for API access.

        This integrates with both JWT and OAuth2 token validation.
        """
        # Let parent class handle OAuth2 token validation
        is_valid = super().validate_bearer_token(token, scopes, request)

        if is_valid:
            logger.debug("Bearer token validated successfully")
        else:
            logger.warning("Bearer token validation failed")

        return is_valid
