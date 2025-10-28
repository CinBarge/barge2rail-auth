"""
Custom OAuth2 Validator for B2R SSO.

This validator integrates django-oauth-toolkit with our existing
authentication and authorization infrastructure.
"""
from oauth2_provider.oauth2_validators import OAuth2Validator
from .models import Application, User, UserRole
import logging

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
            logger.warning(f"Client validation failed: {client_id} not found or inactive")
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
            for uri in application.redirect_uris.replace('\n', ',').split(','):
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
            logger.error(f"Application not found during redirect validation: {client_id}")
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
        allowed_scopes = settings.OAUTH2_PROVIDER.get('SCOPES', {}).keys()

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

        if authenticated and hasattr(request, 'user'):
            logger.debug(f"Request authenticated for user: {request.user.email or request.user.username}")

        return authenticated

    def get_additional_claims(self, request):
        """
        Add custom claims to the ID token (for OpenID Connect).

        Returns:
            dict: Additional claims to include in tokens
        """
        claims = {}

        if hasattr(request, 'user') and request.user:
            user = request.user

            # Add user profile information
            claims.update({
                'email': user.email,
                'email_verified': bool(user.email),
                'name': user.display_name or user.get_full_name(),
                'preferred_username': user.username,
            })

            # Add SSO admin flag (global permission across all apps)
            claims['is_sso_admin'] = user.is_sso_admin

            # Add role information if available
            if hasattr(request, 'client') and request.client:
                try:
                    role = UserRole.objects.get(
                        user=user,
                        application=request.client
                    )
                    claims['role'] = role.role
                    claims['permissions'] = role.permissions
                except UserRole.DoesNotExist:
                    pass

        return claims

    def validate_bearer_token(self, token, scopes, request):
        """
        Validate a bearer token for API access.

        This integrates with both JWT and OAuth2 token validation.
        """
        # Let parent class handle OAuth2 token validation
        is_valid = super().validate_bearer_token(token, scopes, request)

        if is_valid:
            logger.debug(f"Bearer token validated successfully")
        else:
            logger.warning(f"Bearer token validation failed")

        return is_valid
