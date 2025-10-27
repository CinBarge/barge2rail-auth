"""
Custom Authentication Backend for OAuth Admin Integration

This module provides a Django authentication backend that accepts OAuth tokens
instead of traditional username/password credentials.

Security Features:
- Token validation with Google OAuth API
- Email whitelist enforcement
- Automatic permission assignment
- User creation/update from OAuth data
- Comprehensive audit logging
"""

from django.contrib.auth.backends import BaseBackend
from django.contrib.auth import get_user_model
from .utils.session import validate_oauth_token, get_user_from_token
from .utils.permissions import assign_admin_permissions
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


class OAuthBackend(BaseBackend):
    """
    Custom authentication backend for OAuth-based admin access.

    This backend allows users to authenticate using Google OAuth tokens
    instead of traditional username/password credentials. It integrates
    with Django's authentication system to provide seamless admin access.

    Authentication Flow:
    1. Receive OAuth token from request
    2. Validate token with Google OAuth API
    3. Extract user information from token
    4. Get or create Django user
    5. Check email whitelist for admin permissions
    6. Assign appropriate permissions (is_staff, is_superuser)
    7. Return authenticated user

    Security Features:
    - Token validated with Google (not local validation)
    - Email verification required
    - Whitelist enforcement before granting admin access
    - All authentication attempts logged
    - Supports both OAuth and traditional auth (via ModelBackend)

    Usage:
        This backend is registered in settings.py AUTHENTICATION_BACKENDS.
        Django will try each backend in order until one succeeds.

        # settings.py
        AUTHENTICATION_BACKENDS = [
            'sso.backends.OAuthBackend',  # Try OAuth first
            'django.contrib.auth.backends.ModelBackend',  # Fallback to password
        ]

    Examples:
        >>> from django.contrib.auth import authenticate
        >>> user = authenticate(request, oauth_token='ya29.a0AfH6SMB...')
        >>> if user:
        ...     print(f"Authenticated: {user.email}")
        Authenticated: admin@example.com
    """

    def authenticate(self, request, oauth_token=None, **kwargs):
        """
        Authenticate user using OAuth token.

        This method is called by Django's authentication system when
        authenticate() is called with an oauth_token parameter.

        Args:
            request (HttpRequest): Django HttpRequest object
            oauth_token (str): OAuth access token or ID token from Google
            **kwargs: Additional keyword arguments (ignored)

        Returns:
            User: Authenticated Django User object if successful
            None: If authentication fails

        Authentication Steps:
        1. Validate oauth_token parameter exists
        2. Validate token with Google OAuth API
        3. Extract user information (email, name, etc.)
        4. Verify email is present and verified
        5. Get or create Django user from email
        6. Check email against admin whitelist
        7. Assign admin permissions if whitelisted
        8. Update user information if changed
        9. Return authenticated user

        Security Notes:
        - Token validated with Google (not local validation)
        - Email verification required (email_verified=True)
        - Permissions only granted if email whitelisted
        - All authentication attempts logged
        - Failed authentications return None (not exceptions)

        Examples:
            >>> # In a view
            >>> from django.contrib.auth import authenticate
            >>> user = authenticate(request, oauth_token=token)
            >>> if user:
            ...     login(request, user)

            >>> # With invalid token
            >>> user = authenticate(request, oauth_token='invalid')
            >>> print(user)
            None
        """
        # Require oauth_token parameter
        if oauth_token is None:
            logger.debug("OAuthBackend.authenticate called without oauth_token")
            return None

        logger.debug(f"OAuthBackend.authenticate called with token")

        try:
            # Step 1: Validate OAuth token with Google
            token_valid, user_info = validate_oauth_token(oauth_token)

            if not token_valid:
                logger.warning("OAuth token validation failed in authenticate()")
                return None

            # Step 2: Extract email
            email = user_info.get('email')
            if not email:
                logger.error("No email in OAuth user info")
                return None

            logger.debug(f"OAuth token validated for {email}")

            # Step 3: Get or create user from token info
            user = get_user_from_token(user_info)

            if not user:
                logger.error(f"Failed to get/create user for {email}")
                return None

            # Step 4: Assign admin permissions based on whitelist
            # This checks ADMIN_WHITELIST and SUPERUSER_WHITELIST
            is_staff, is_superuser, changed = assign_admin_permissions(user)

            if changed:
                logger.info(
                    f"OAuth authentication: permissions updated for {email} "
                    f"(is_staff={is_staff}, is_superuser={is_superuser})"
                )

            # Step 5: Log successful authentication
            logger.info(
                f"OAuth authentication successful: {email} "
                f"(is_staff={user.is_staff}, is_superuser={user.is_superuser})"
            )

            return user

        except Exception as e:
            # Catch any unexpected errors
            logger.error(
                f"Unexpected error in OAuthBackend.authenticate: {str(e)}",
                exc_info=True
            )
            return None

    def get_user(self, user_id):
        """
        Get user by ID (required by Django authentication system).

        This method is called by Django to retrieve a user object from
        a user ID stored in the session. It's required for session-based
        authentication to work properly.

        Args:
            user_id: Primary key of the user (UUID in this project)

        Returns:
            User: Django User object if found
            None: If user doesn't exist or error occurs

        Django Usage:
            Django calls this method automatically when:
            - Retrieving user from session (request.user)
            - Checking if user is authenticated
            - Validating session after login

        Security Notes:
            - Returns None for invalid user_id (no exceptions)
            - Returns None for inactive users (is_active=False)
            - Logs lookup failures for debugging

        Examples:
            >>> backend = OAuthBackend()
            >>> user = backend.get_user('123e4567-e89b-12d3-a456-426614174000')
            >>> if user:
            ...     print(user.email)
            admin@example.com
        """
        try:
            # Look up user by primary key
            user = User.objects.get(pk=user_id)

            # Only return active users
            if not user.is_active:
                logger.warning(
                    f"get_user called for inactive user: {user.email} (id={user_id})"
                )
                return None

            logger.debug(f"get_user: Found user {user.email} (id={user_id})")
            return user

        except User.DoesNotExist:
            logger.debug(f"get_user: User not found (id={user_id})")
            return None

        except Exception as e:
            logger.error(
                f"Unexpected error in OAuthBackend.get_user: {str(e)}",
                exc_info=True
            )
            return None

    def user_can_authenticate(self, user):
        """
        Check if user is allowed to authenticate.

        This method is called by Django to determine if a user object
        is allowed to authenticate. By default, it checks is_active.

        Args:
            user: Django User object

        Returns:
            bool: True if user can authenticate, False otherwise

        Django Usage:
            Django calls this automatically during authentication.
            Override this method to add custom authentication rules.

        Security Notes:
            - Default implementation checks is_active flag
            - Can be overridden for additional checks
            - Called after authenticate() succeeds

        Examples:
            >>> backend = OAuthBackend()
            >>> user = User.objects.get(email='admin@example.com')
            >>> can_auth = backend.user_can_authenticate(user)
            >>> print(can_auth)
            True
        """
        # Default behavior: only active users can authenticate
        is_active = getattr(user, 'is_active', None)
        return is_active or is_active is None
