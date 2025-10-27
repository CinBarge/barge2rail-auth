"""
Session Management Utilities for OAuth Admin Integration

This module handles OAuth token validation and Django session creation.
It provides functions to validate Google OAuth tokens and create admin sessions.

Security Features:
- Token validation with Google OAuth API
- User creation/update with OAuth data
- Django session creation for admin access
- Session hash validation
- Comprehensive error logging
"""

from django.contrib.auth import get_user_model
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

User = get_user_model()

# Try to import Google OAuth libraries
try:
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False
    logger.warning(
        "Google auth libraries not available. "
        "Install with: pip install google-auth google-auth-oauthlib"
    )


def validate_oauth_token(token):
    """
    Validate OAuth token with Google and extract user info.

    This function validates either an ID token or access token with Google's
    OAuth API and extracts user information if valid.

    Args:
        token (str): OAuth access token or ID token from Google

    Returns:
        tuple: (bool: is_valid, dict: user_info or None)
            - is_valid: True if token is valid and verified
            - user_info: Dictionary with keys:
                - email: User's email address
                - email_verified: Boolean, email verification status
                - given_name: User's first name
                - family_name: User's last name
                - picture: URL to user's profile picture
                - sub: Google user ID

    Security Notes:
        - Verifies token with Google OAuth API (not local validation)
        - Requires email_verified=True (rejects unverified emails)
        - Returns None for invalid/expired tokens
        - Logs all validation attempts

    Examples:
        >>> token = "ya29.a0AfH6SMB..."  # Google OAuth token
        >>> is_valid, user_info = validate_oauth_token(token)
        >>> if is_valid:
        ...     print(user_info['email'])
        admin@example.com
    """
    if not token:
        logger.warning("validate_oauth_token called with empty token")
        return (False, None)

    if not GOOGLE_AUTH_AVAILABLE:
        logger.error(
            "Cannot validate OAuth token - Google auth libraries not installed"
        )
        return (False, None)

    try:
        # Get Google client ID from settings
        google_client_id = getattr(settings, 'GOOGLE_CLIENT_ID', '')
        if not google_client_id:
            logger.error("GOOGLE_CLIENT_ID not configured in settings")
            return (False, None)

        # Verify the ID token with Google
        # Note: This assumes token is an ID token. For access tokens,
        # you would need to call Google's tokeninfo endpoint instead.
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            google_client_id
        )

        # Extract user information
        user_info = {
            'email': idinfo.get('email'),
            'email_verified': idinfo.get('email_verified', False),
            'given_name': idinfo.get('given_name', ''),
            'family_name': idinfo.get('family_name', ''),
            'picture': idinfo.get('picture', ''),
            'sub': idinfo.get('sub'),  # Google user ID
        }

        # Security: Ensure email is verified
        if not user_info.get('email_verified'):
            logger.warning(
                f"OAuth token has unverified email: {user_info.get('email')}"
            )
            return (False, None)

        if not user_info.get('email'):
            logger.error("OAuth token missing email field")
            return (False, None)

        logger.debug(f"OAuth token validated successfully for {user_info['email']}")
        return (True, user_info)

    except ValueError as e:
        # Token validation failed (invalid token, expired, wrong audience, etc.)
        logger.warning(f"OAuth token validation failed: {str(e)}")
        return (False, None)

    except Exception as e:
        # Unexpected error
        logger.error(f"Unexpected error validating OAuth token: {str(e)}", exc_info=True)
        return (False, None)


def get_user_from_token(user_info):
    """
    Get or create Django user from OAuth user info.

    This function retrieves an existing user or creates a new one based on
    OAuth user information. It updates user's name if it has changed.

    Args:
        user_info (dict): Dictionary with user information from OAuth
            Required keys:
                - email: User's email address
            Optional keys:
                - given_name: User's first name
                - family_name: User's last name

    Returns:
        User: Django User object, or None if error

    Side Effects:
        - Creates new user if email doesn't exist
        - Updates user's first_name and last_name if changed
        - Sets username to email (since USERNAME_FIELD='email')
        - Logs user creation/update

    Security Notes:
        - Only creates/updates from validated OAuth data
        - Does not set password (OAuth-only authentication)
        - Email must be provided

    Examples:
        >>> user_info = {
        ...     'email': 'user@example.com',
        ...     'given_name': 'John',
        ...     'family_name': 'Doe',
        ... }
        >>> user = get_user_from_token(user_info)
        >>> print(f"{user.first_name} {user.last_name}")
        John Doe
    """
    if not user_info or not user_info.get('email'):
        logger.error("get_user_from_token called with invalid user_info")
        return None

    email = user_info['email'].lower().strip()

    try:
        # Try to get existing user
        try:
            user = User.objects.get(email=email)
            logger.debug(f"Found existing user: {email}")

            # Update user info if it changed
            updated = False
            given_name = user_info.get('given_name', '')
            family_name = user_info.get('family_name', '')

            if user.first_name != given_name:
                user.first_name = given_name
                updated = True

            if user.last_name != family_name:
                user.last_name = family_name
                updated = True

            if updated:
                user.save(update_fields=['first_name', 'last_name'])
                logger.info(f"Updated user info for {email}")

            return user

        except User.DoesNotExist:
            # User doesn't exist - create new user
            logger.info(f"Creating new user from OAuth: {email}")

            # Generate username from email (since USERNAME_FIELD='email')
            # but username field still needs a value
            username = email.split('@')[0]

            # Ensure username is unique
            base_username = username
            counter = 1
            while User.objects.filter(username=username).exists():
                username = f"{base_username}{counter}"
                counter += 1

            # Create user
            user = User.objects.create(
                email=email,
                username=username,
                first_name=user_info.get('given_name', ''),
                last_name=user_info.get('family_name', ''),
                auth_method='google',  # Mark as Google OAuth user
                is_active=True,
            )

            logger.info(f"Created new user: {email} (username: {username})")
            return user

    except Exception as e:
        logger.error(f"Error getting/creating user from token: {str(e)}", exc_info=True)
        return None


def create_admin_session(request, user):
    """
    Create Django admin session for OAuth-authenticated user.

    This function creates a Django session for an OAuth-authenticated user,
    allowing them to access the Django admin interface without traditional
    username/password authentication.

    Args:
        request (HttpRequest): Django HttpRequest object
        user (User): Django User object

    Returns:
        bool: True if session created successfully, False otherwise

    Side Effects:
        - Sets session authentication keys
        - Sets session OAuth indicator
        - Saves session to database
        - Logs session creation

    Security Notes:
        - Uses Django's built-in session management
        - Includes session auth hash for security
        - Marks session as OAuth-authenticated
        - Logs all session creation

    Examples:
        >>> from django.http import HttpRequest
        >>> request = HttpRequest()
        >>> user = User.objects.get(email='admin@example.com')
        >>> success = create_admin_session(request, user)
        >>> print(f"Session created: {success}")
        Session created: True
    """
    if not request:
        logger.error("create_admin_session called with no request")
        return False

    if not user:
        logger.error("create_admin_session called with invalid user")
        return False

    if not user.is_active:
        logger.error(f"create_admin_session called with inactive user: {user.email}")
        return False

    try:
        # Set Django session authentication keys
        # These are the keys Django uses to identify authenticated users
        request.session['_auth_user_id'] = str(user.pk)
        request.session['_auth_user_backend'] = 'sso.backends.OAuthBackend'
        request.session['_auth_user_hash'] = user.get_session_auth_hash()

        # Store OAuth indicator
        request.session['oauth_authenticated'] = True

        # Store timestamp
        from django.utils import timezone
        request.session['oauth_authenticated_at'] = timezone.now().isoformat()

        # Save session
        request.session.save()

        logger.info(
            f"Created admin session for {user.email} "
            f"(session_key: {request.session.session_key[:10]}...)"
        )
        return True

    except Exception as e:
        logger.error(f"Error creating admin session: {str(e)}", exc_info=True)
        return False
