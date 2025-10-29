"""
Session security middleware for barge2rail-auth.
Gate 7: Session Security Hardening

OAuth Admin Integration Middleware:
- OAuthAdminMiddleware: Validates OAuth tokens for admin access
"""

import logging

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.urls import resolve
from django.utils import timezone

logger = logging.getLogger("django.security")
oauth_logger = logging.getLogger("sso")


class SessionActivityMiddleware:
    """
    Track session activity and enforce idle timeout.

    This middleware:
    1. Tracks last activity timestamp for each session
    2. Enforces 30-minute idle timeout
    3. Logs security events (timeouts)
    4. Provides user feedback on timeout
    """

    IDLE_TIMEOUT_SECONDS = 1800  # 30 minutes

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            current_time = timezone.now()
            last_activity = request.session.get("last_activity")

            if last_activity:
                try:
                    # Parse stored timestamp
                    last_activity_time = timezone.datetime.fromisoformat(last_activity)

                    # Calculate idle time
                    idle_seconds = (current_time - last_activity_time).total_seconds()

                    # Check if session has been idle too long
                    if idle_seconds > self.IDLE_TIMEOUT_SECONDS:
                        user_email = request.user.email
                        idle_minutes = int(idle_seconds / 60)

                        logger.info(
                            f"Session timeout - User: {user_email}, "
                            f"Idle: {idle_minutes} minutes, "
                            f"IP: {request.META.get('REMOTE_ADDR')}"
                        )

                        # Log out user
                        logout(request)

                        # Set message for next request (after redirect)
                        request.session["timeout_message"] = (
                            "Your session expired due to inactivity. "
                            "Please log in again."
                        )

                        # Don't update last_activity - user is being logged out
                        response = self.get_response(request)
                        return response

                except (ValueError, AttributeError, TypeError) as e:
                    # Invalid timestamp format - reset it
                    logger.warning(
                        f"Invalid last_activity timestamp: {last_activity} - "
                        f"Error: {e}"
                    )

            # Update last activity for this request
            request.session["last_activity"] = current_time.isoformat()

        response = self.get_response(request)
        return response


class OAuthAdminMiddleware:
    """
    OAuth token validation middleware for Django admin access.

    This middleware enables OAuth-based authentication for the Django admin
    interface while preserving traditional password-based authentication as
    a fallback for emergency access.

    Features:
    - OAuth token validation from Authorization header
    - OAuth token validation from session storage
    - Automatic user authentication via OAuthBackend
    - Transparent pass-through for password-based auth
    - Admin-only enforcement (doesn't affect other URLs)
    - Comprehensive security logging

    Flow:
    1. Check if request is for admin interface
    2. If user already authenticated (password or previous OAuth), allow
    3. If not authenticated, check for OAuth token
    4. If OAuth token present, validate and authenticate
    5. If no token or invalid, allow request to continue (Django handles login)

    Security Notes:
    - Does NOT block password-based authentication (emergency access)
    - Only processes admin URLs (doesn't interfere with API endpoints)
    - Logs all OAuth authentication attempts
    - Validates tokens with Google OAuth API (not local validation)

    Usage:
        Add to MIDDLEWARE in settings.py:
        MIDDLEWARE = [
            ...
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'sso.middleware.OAuthAdminMiddleware',  # After AuthenticationMiddleware
            ...
        ]
    """

    def __init__(self, get_response):
        """
        Initialize middleware.

        Args:
            get_response: Django request/response handler
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Process request for OAuth authentication.

        Args:
            request (HttpRequest): Django request object

        Returns:
            HttpResponse: Response from next middleware or view

        Flow:
        1. Check if admin URL
        2. Check if user already authenticated
        3. Check for OAuth token in Authorization header or session
        4. Validate token and authenticate user
        5. Continue to next middleware/view
        """
        # Only process admin requests
        if not self._is_admin_request(request):
            return self.get_response(request)

        # If user already authenticated (password or previous OAuth), allow through
        if request.user.is_authenticated:
            oauth_logger.debug(
                f"OAuthAdminMiddleware: User already authenticated: {request.user.email}"
            )
            return self.get_response(request)

        # Check for OAuth token
        oauth_token = self._get_oauth_token(request)

        if not oauth_token:
            # No OAuth token - allow request to continue
            # Django's admin will handle login redirect
            oauth_logger.debug(
                "OAuthAdminMiddleware: No OAuth token found, "
                "allowing Django admin to handle authentication"
            )
            return self.get_response(request)

        # Validate and authenticate with OAuth token
        oauth_logger.debug(
            "OAuthAdminMiddleware: OAuth token found, attempting authentication"
        )
        user = self._authenticate_with_oauth(request, oauth_token)

        if user:
            # Authentication successful
            oauth_logger.info(
                f"OAuthAdminMiddleware: User authenticated via OAuth: {user.email}"
            )
            # User is now logged in via Django's session
            # Admin access will be granted based on is_staff/is_superuser
        else:
            # Token invalid or authentication failed
            oauth_logger.warning("OAuthAdminMiddleware: OAuth token validation failed")

        # Continue with request
        response = self.get_response(request)
        return response

    def _is_admin_request(self, request):
        """
        Check if request is for Django admin interface.

        Args:
            request (HttpRequest): Django request object

        Returns:
            bool: True if admin request, False otherwise

        Implementation:
            Checks if URL path starts with /admin/
            This covers all admin URLs including login, dashboard, models, etc.
        """
        path = request.path_info
        is_admin = path.startswith("/admin/")

        if is_admin:
            oauth_logger.debug(f"OAuthAdminMiddleware: Admin request detected: {path}")

        return is_admin

    def _get_oauth_token(self, request):
        """
        Extract OAuth token from request.

        Checks two locations in order:
        1. Authorization header (Bearer token)
        2. Session storage (from OAuth callback)

        Args:
            request (HttpRequest): Django request object

        Returns:
            str: OAuth token if found, None otherwise

        Token Formats:
        - Header: "Authorization: Bearer <token>"
        - Session: request.session['oauth_token']

        Security Notes:
        - Tokens are sensitive - never logged in full
        - Authorization header takes precedence
        - Session tokens are temporary (cleared after use)
        """
        # Check Authorization header first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            oauth_logger.debug(
                f"OAuthAdminMiddleware: OAuth token found in Authorization header "
                f"(length: {len(token)})"
            )
            return token

        # Check session storage
        session_token = request.session.get("oauth_token")
        if session_token:
            oauth_logger.debug(
                f"OAuthAdminMiddleware: OAuth token found in session "
                f"(length: {len(session_token)})"
            )
            return session_token

        return None

    def _authenticate_with_oauth(self, request, oauth_token):
        """
        Authenticate user with OAuth token.

        Uses Django's authenticate() function with OAuthBackend to:
        1. Validate token with Google
        2. Get or create user
        3. Assign admin permissions based on whitelist
        4. Create Django session

        Args:
            request (HttpRequest): Django request object
            oauth_token (str): OAuth access token or ID token

        Returns:
            User: Authenticated user object if successful, None otherwise

        Side Effects:
        - Logs user in via Django's session (login() called)
        - Clears OAuth token from session (security)
        - Logs authentication result

        Security Notes:
        - Token validated with Google (via OAuthBackend)
        - Permissions assigned based on whitelist
        - Failed authentications logged for audit
        """
        try:
            # Use Django's authenticate() - will try OAuthBackend first
            user = authenticate(request, oauth_token=oauth_token)

            if user:
                # Authentication successful - log user in
                login(request, user, backend="sso.backends.OAuthBackend")

                oauth_logger.info(
                    f"OAuthAdminMiddleware: User logged in: {user.email} "
                    f"(is_staff={user.is_staff}, is_superuser={user.is_superuser})"
                )

                # Clear OAuth token from session (security best practice)
                if "oauth_token" in request.session:
                    del request.session["oauth_token"]
                    oauth_logger.debug(
                        "OAuthAdminMiddleware: Cleared OAuth token from session"
                    )

                return user
            else:
                # Authentication failed
                oauth_logger.warning(
                    "OAuthAdminMiddleware: OAuth authentication failed - "
                    "token invalid or user not authorized"
                )
                return None

        except Exception as e:
            # Unexpected error
            oauth_logger.error(
                f"OAuthAdminMiddleware: Unexpected error during OAuth authentication: {str(e)}",
                exc_info=True,
            )
            return None
