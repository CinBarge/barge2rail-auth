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

    # =========================================================================
    # OIDC Custom Claims for JWT ID Tokens
    # =========================================================================

    # Scope-to-claim mapping (security: only return claims when scope requested)
    oidc_claim_scope = (
        OAuth2Validator.oidc_claim_scope.copy()
        if hasattr(OAuth2Validator, "oidc_claim_scope")
        else {}
    )
    oidc_claim_scope.update(
        {
            "application_roles": "roles",  # Only include when 'roles' scope requested
            "email": "email",
            "name": "profile",
            "is_sso_admin": "profile",
        }
    )

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
        Add custom claims to ID token for OIDC.

        Called by django-oauth-toolkit during ID token generation.
        Returns dict of custom claims to include in JWT.

        Args:
            request: OAuth2 request object with user/client context

        Returns:
            dict: Custom claims to merge into ID token
        """
        logger.info("[CLAIMS] get_additional_claims() called")

        claims = {}

        # Get user from request (try multiple paths for robustness)
        user = None
        if hasattr(request, "user") and request.user:
            user = request.user
            user_id = user.email if hasattr(user, "email") else user.username
            logger.info(f"[CLAIMS] User found via request.user: {user_id}")
        elif hasattr(request, "client") and hasattr(request.client, "user"):
            user = request.client.user
            user_id = user.email if hasattr(user, "email") else user.username
            logger.info(f"[CLAIMS] User found via request.client.user: {user_id}")
        else:
            logger.warning("[CLAIMS] No user found in request")

        # Add claims only if user is authenticated
        if user and user.is_authenticated:
            # Basic user profile claims
            claims.update(
                {
                    "email": user.email or "",
                    "email_verified": bool(user.email),
                    "name": user.get_full_name() or user.display_name or user.username,
                    "preferred_username": user.username,
                }
            )

            logger.info(f"[CLAIMS] Added basic profile claims for {user.email}")

            # Application-specific roles from ApplicationRole model
            try:
                from .models import ApplicationRole

                app_roles_qs = ApplicationRole.objects.filter(user=user).only(
                    "application", "role", "permissions"
                )

                logger.info(f"[CLAIMS] Querying ApplicationRole for user {user.email}")
                logger.info(
                    f"[CLAIMS] Found {app_roles_qs.count()} ApplicationRole records"
                )

                application_roles = {}
                for ar in app_roles_qs:
                    application_roles[ar.application.slug] = {
                        "role": ar.role,
                        "permissions": ar.permissions or [],
                    }
                    logger.info(
                        f"[CLAIMS] Added role: {ar.application.slug} -> {ar.role}"
                    )

                    # Add feature-level permissions from RBAC system (UserAppRole)
                    try:
                        from .models import UserAppRole

                        user_app_role = (
                            UserAppRole.objects.select_related("role")
                            .prefetch_related(
                                "role__feature_permissions__feature",
                                "role__feature_permissions__permission",
                            )
                            .get(
                                user=user,
                                role__application=ar.application,
                                is_active=True,
                            )
                        )
                        feature_perms = user_app_role.get_permissions()
                        if feature_perms:
                            application_roles[ar.application.slug][
                                "features"
                            ] = feature_perms
                            logger.info(
                                f"[CLAIMS] Added RBAC features for "
                                f"{ar.application.slug}: {list(feature_perms.keys())}"
                            )
                    except UserAppRole.DoesNotExist:
                        logger.info(
                            f"[CLAIMS] No UserAppRole found for "
                            f"{ar.application.slug}, skipping features"
                        )
                    except UserAppRole.MultipleObjectsReturned:
                        # Use first active one if multiple exist
                        user_app_role = (
                            UserAppRole.objects.select_related("role")
                            .prefetch_related(
                                "role__feature_permissions__feature",
                                "role__feature_permissions__permission",
                            )
                            .filter(
                                user=user,
                                role__application=ar.application,
                                is_active=True,
                            )
                            .first()
                        )
                        if user_app_role:
                            feature_perms = user_app_role.get_permissions()
                            if feature_perms:
                                application_roles[ar.application.slug][
                                    "features"
                                ] = feature_perms
                                logger.info(
                                    "[CLAIMS] Added RBAC features (multi) "
                                    "for %s: %s",
                                    ar.application.slug,
                                    list(feature_perms.keys()),
                                )

                if application_roles:
                    claims["application_roles"] = application_roles
                    app_list = list(application_roles.keys())
                    logger.info(
                        f"[CLAIMS] application_roles claim added with "
                        f"{len(application_roles)} apps: {app_list}"
                    )
                else:
                    logger.warning(
                        f"[CLAIMS] No ApplicationRole records found "
                        f"for user {user.email}"
                    )

            except ImportError as e:
                logger.error(f"[CLAIMS] Failed to import ApplicationRole model: {e}")
            except Exception as e:
                logger.error(f"[CLAIMS] Error building application_roles claim: {e}")

            # SSO admin flag (if attribute exists)
            if hasattr(user, "is_sso_admin"):
                claims["is_sso_admin"] = user.is_sso_admin
                logger.info(f"[CLAIMS] Added is_sso_admin: {user.is_sso_admin}")

            # Backward compatibility: Add per-client role if available
            # (Supports legacy clients that expect 'role' claim)
            if hasattr(request, "client") and request.client:
                try:
                    role = UserRole.objects.get(user=user, application=request.client)
                    claims["role"] = role.role
                    claims["permissions"] = role.permissions
                    logger.info(f"[CLAIMS] Added legacy role claim: {role.role}")
                except UserRole.DoesNotExist:
                    pass
                except Exception as e:
                    logger.error(f"[CLAIMS] Error adding legacy role: {e}")
        else:
            logger.warning("[CLAIMS] User not authenticated, returning empty claims")

        logger.info(f"[CLAIMS] Returning claims with keys: {list(claims.keys())}")
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
