"""
Admin OAuth Views for Django Admin Integration

This module provides OAuth-based authentication views specifically for
Django admin access. These views handle the OAuth flow for admin users,
integrating with OAuthBackend and OAuthAdminMiddleware.

Views:
- admin_oauth_login: Initiates Google OAuth flow for admin access
- admin_oauth_callback: Handles OAuth callback and admin authentication

Security Features:
- State parameter for CSRF protection
- ID token validation with Google
- Integration with OAuthBackend for admin permission assignment
- Session-based token storage for middleware
"""

import logging
import secrets
import time
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.shortcuts import redirect
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit

# Import OAuth utilities from existing infrastructure
try:
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False

logger = logging.getLogger("sso")


# ===========================================================================
# OAuth State Parameter Helpers (CSRF Protection)
# ===========================================================================


def generate_oauth_state():
    """
    Generate secure OAuth state parameter for CSRF protection.

    Format: {random_token}:{timestamp}

    Returns:
        str: Secure state token with embedded timestamp
    """
    token = secrets.token_urlsafe(32)
    timestamp = str(int(time.time()))
    return f"{token}:{timestamp}"


def validate_oauth_state(state_from_callback, state_from_session, timeout=300):
    """
    Validate OAuth state parameter for CSRF protection.

    Args:
        state_from_callback (str): State parameter from OAuth callback
        state_from_session (str): State stored in session during initiation
        timeout (int): Maximum age in seconds (default 300 seconds = 5 minutes)

    Returns:
        bool: True if valid, False otherwise

    Security Notes:
        - Prevents CSRF attacks via state validation
        - Prevents replay attacks via timestamp validation
        - One-time use (session state cleared after validation)
    """
    if not state_from_callback or not state_from_session:
        logger.warning("OAuth state validation failed: Missing state parameter")
        return False

    if state_from_callback != state_from_session:
        logger.warning(
            f"OAuth state validation failed: State mismatch "
            f"(callback: {state_from_callback[:10]}..., session: {state_from_session[:10]}...)"
        )
        return False

    # Check timestamp to prevent replay attacks
    try:
        _, timestamp_str = state_from_session.split(":")
        timestamp = int(timestamp_str)
        age = int(time.time()) - timestamp
        if age > timeout:
            logger.warning(
                f"OAuth state validation failed: State expired (age: {age}s)"
            )
            return False
    except (ValueError, AttributeError) as e:
        logger.warning(f"OAuth state validation failed: Invalid format - {e}")
        return False

    return True


# ===========================================================================
# Admin OAuth Views
# ===========================================================================


@require_http_methods(["GET"])
@ratelimit(key="ip", rate="10/h", method="GET", block=True)
def admin_oauth_login(request):
    """
    Initiate Google OAuth flow for Django admin access.

    This view redirects the user to Google's OAuth consent screen.
    After consent, Google redirects back to admin_oauth_callback.

    Flow:
    1. Generate secure state token (CSRF protection)
    2. Store state in session
    3. Build Google OAuth authorization URL
    4. Redirect user to Google consent screen

    Query Parameters:
        next (optional): URL to redirect to after successful authentication
                        Defaults to /admin/ if not provided

    Returns:
        HttpResponseRedirect: Redirect to Google OAuth consent screen

    Security:
        - Generates state token for CSRF protection
        - Stores state in Django session (server-side)
        - State validated on callback
        - Next URL stored for post-auth redirect

    Examples:
        GET /sso/admin/oauth/login/
        GET /sso/admin/oauth/login/?next=/admin/users/
    """
    logger.info("admin_oauth_login: Initiating OAuth flow for admin access")

    # Check if Google OAuth is configured
    if not GOOGLE_AUTH_AVAILABLE:
        logger.error("admin_oauth_login: Google auth libraries not installed")
        messages.error(
            request, "Google authentication is not available. Please contact support."
        )
        return redirect("/cbrt-ops/login/")

    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        logger.error("admin_oauth_login: Google OAuth not configured")
        messages.error(
            request, "Google OAuth is not configured. Please contact support."
        )
        return redirect("/cbrt-ops/login/")

    # Generate and store state parameter for CSRF protection
    state = generate_oauth_state()

    # CRITICAL: Force session creation before redirect
    # Without this, session cookie won't be set and state will be lost
    if not request.session.session_key:
        request.session.create()

    request.session["admin_oauth_state"] = state
    request.session["admin_oauth_next"] = request.GET.get("next", "/cbrt-ops/")

    # Mark session as modified to ensure cookie is set
    request.session.modified = True

    logger.info(
        f"admin_oauth_login: Generated OAuth state token (length: {len(state)})"
    )

    # Build redirect URI (where Google will send user after authentication)
    redirect_uri = f"{settings.BASE_URL}/sso/admin/oauth/callback/"

    # Build Google OAuth authorization URL
    google_oauth_params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
        "state": state,  # CSRF protection
    }

    google_auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(google_oauth_params)}"
    )

    logger.info("admin_oauth_login: Redirecting to Google OAuth consent screen")

    # Create response and explicitly save session before redirect
    response = redirect(google_auth_url)
    request.session.save()
    return response


@require_http_methods(["GET"])
@ratelimit(key="ip", rate="10/h", method="GET", block=True)
def admin_oauth_callback(request):
    """
    Handle Google OAuth callback for Django admin access.

    This view is called by Google after the user grants consent.
    It exchanges the authorization code for tokens, validates the user,
    and logs them into Django admin.

    Flow:
    1. Validate state parameter (CSRF protection)
    2. Extract authorization code from query parameters
    3. Exchange code for ID token
    4. Validate ID token with Google
    5. Authenticate user via OAuthBackend
    6. Store ID token in session for middleware
    7. Redirect to admin or next URL

    Query Parameters:
        code (required): Authorization code from Google
        state (required): State token for CSRF validation
        error (optional): Error code if user denied access

    Returns:
        HttpResponseRedirect: Redirect to Django admin or error page

    Security:
        - Validates state parameter (CSRF protection)
        - Validates ID token with Google (not local validation)
        - Uses OAuthBackend for authentication and permission assignment
        - Stores token in session (not in URL or cookies)
        - Clears state from session (one-time use)

    Error Handling:
        - User denied access: Redirects to /admin/login/ with error message
        - Invalid state: Redirects to /admin/login/ with security warning
        - Token validation failed: Redirects to /admin/login/ with error
        - Authentication failed: Redirects to /admin/login/ with permission error

    Examples:
        GET /sso/admin/oauth/callback/?code=...&state=...
    """
    logger.info("admin_oauth_callback: Processing OAuth callback")

    # Check for OAuth errors (user denied access, etc.)
    error = request.GET.get("error")
    if error:
        logger.warning(f"admin_oauth_callback: OAuth error: {error}")
        messages.warning(
            request, "Google authentication was cancelled. Please try again."
        )
        return redirect("/cbrt-ops/login/")

    # Extract parameters
    code = request.GET.get("code")
    state_from_callback = request.GET.get("state")

    if not code:
        logger.error("admin_oauth_callback: Missing authorization code")
        messages.error(request, "Authentication failed: Missing authorization code.")
        return redirect("/cbrt-ops/login/")

    # Validate state parameter (CSRF protection)
    state_from_session = request.session.get("admin_oauth_state")

    if not validate_oauth_state(state_from_callback, state_from_session):
        logger.error(
            "admin_oauth_callback: State validation failed - possible CSRF attack"
        )
        messages.error(request, "Authentication failed: Security validation failed.")
        # Clear session state
        if "admin_oauth_state" in request.session:
            del request.session["admin_oauth_state"]
        if "admin_oauth_next" in request.session:
            del request.session["admin_oauth_next"]
        return redirect("/cbrt-ops/login/")

    # Clear state from session (one-time use)
    del request.session["admin_oauth_state"]
    logger.info("admin_oauth_callback: State validated and cleared")

    try:
        # Exchange authorization code for tokens
        logger.info("admin_oauth_callback: Exchanging authorization code for tokens")
        token_data = exchange_google_code_for_tokens(code)

        if "error" in token_data:
            logger.error(f"admin_oauth_callback: Token exchange error: {token_data}")
            messages.error(
                request, "Authentication failed: Could not exchange authorization code."
            )
            return redirect("/cbrt-ops/login/")

        # Extract ID token
        id_token_str = token_data.get("id_token")
        if not id_token_str:
            logger.error("admin_oauth_callback: No ID token in response")
            messages.error(request, "Authentication failed: Invalid token response.")
            return redirect("/cbrt-ops/login/")

        logger.info("admin_oauth_callback: ID token received, validating with Google")

        # Validate ID token with Google and extract user info
        user_info = validate_google_id_token(id_token_str)

        if not user_info:
            logger.error("admin_oauth_callback: ID token validation failed")
            messages.error(request, "Authentication failed: Token validation failed.")
            return redirect("/cbrt-ops/login/")

        logger.info(
            f"admin_oauth_callback: ID token validated for {user_info.get('email')}"
        )

        # Authenticate user via OAuthBackend
        # This will:
        # 1. Validate token again (via OAuthBackend)
        # 2. Get or create user
        # 3. Assign admin permissions based on whitelist
        user = authenticate(request, oauth_token=id_token_str)

        if not user:
            logger.warning(
                f"admin_oauth_callback: Authentication failed for {user_info.get('email')} "
                "(user not in whitelist or authentication error)"
            )
            messages.error(
                request,
                "Authentication failed: You do not have permission to access the admin interface. "
                "Please contact an administrator if you believe this is an error.",
            )
            return redirect("/cbrt-ops/login/")

        # Check if user has admin permissions
        if not user.is_staff:
            logger.warning(
                f"admin_oauth_callback: User {user.email} authenticated but not staff"
            )
            messages.error(
                request,
                "You do not have permission to access the admin interface. "
                "Please contact an administrator.",
            )
            return redirect("/cbrt-ops/login/")

        # Log user in via Django session
        login(request, user, backend="sso.backends.OAuthBackend")
        logger.info(
            f"admin_oauth_callback: User {user.email} logged in successfully "
            f"(is_staff={user.is_staff}, is_superuser={user.is_superuser})"
        )

        # Store ID token in session for OAuthAdminMiddleware
        # This allows middleware to validate on subsequent requests
        request.session["oauth_token"] = id_token_str
        logger.info("admin_oauth_callback: Stored OAuth token in session")

        # Get next URL from session (or default to /admin/)
        next_url = request.session.pop("admin_oauth_next", "/cbrt-ops/")
        logger.info(f"admin_oauth_callback: Redirecting to {next_url}")

        # Success message
        messages.success(request, f"Welcome, {user.get_full_name() or user.email}!")

        return redirect(next_url)

    except Exception as e:
        logger.error(f"admin_oauth_callback: Unexpected error: {str(e)}", exc_info=True)
        messages.error(request, "Authentication failed: An unexpected error occurred.")

        # Clear session state
        if "admin_oauth_state" in request.session:
            del request.session["admin_oauth_state"]
        if "admin_oauth_next" in request.session:
            del request.session["admin_oauth_next"]

        return redirect("/cbrt-ops/login/")


# ===========================================================================
# Token Exchange Helpers
# ===========================================================================


def exchange_google_code_for_tokens(code):
    """
    Exchange Google authorization code for access and ID tokens.

    Args:
        code (str): Authorization code from Google OAuth callback

    Returns:
        dict: Token response containing:
            - access_token: OAuth access token
            - id_token: JWT ID token with user info
            - expires_in: Token expiration time
            - refresh_token: Refresh token (if requested)
        OR
        dict: Error response containing:
            - error: Error code
            - error_description: Human-readable error description

    Implementation:
        Makes POST request to Google's token endpoint with:
        - Authorization code
        - Client ID and secret
        - Redirect URI (must match the one used for authorization)

    Security:
        - Uses HTTPS for token exchange
        - Client secret never exposed to client
        - Tokens returned to server only (not to browser)
    """
    token_url = "https://oauth2.googleapis.com/token"

    redirect_uri = f"{settings.BASE_URL}/sso/admin/oauth/callback/"

    data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    try:
        import requests

        response = requests.post(token_url, data=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"exchange_google_code_for_tokens: Error - {str(e)}")
        return {"error": "token_exchange_failed", "error_description": str(e)}


def validate_google_id_token(id_token_str):
    """
    Validate Google ID token and extract user information.

    Args:
        id_token_str (str): JWT ID token from Google

    Returns:
        dict: User information extracted from token:
            - email: User's email address
            - email_verified: Boolean, email verification status
            - given_name: User's first name
            - family_name: User's last name
            - picture: URL to user's profile picture
            - sub: Google user ID
        OR
        None: If validation fails

    Security:
        - Validates token signature with Google's public keys
        - Validates token issuer (must be accounts.google.com)
        - Validates token audience (must match our client ID)
        - Validates token expiration
        - Requires email_verified=True
    """
    if not GOOGLE_AUTH_AVAILABLE:
        logger.error("validate_google_id_token: Google auth libraries not available")
        return None

    try:
        # Verify the ID token with Google
        idinfo = id_token.verify_oauth2_token(
            id_token_str, google_requests.Request(), settings.GOOGLE_CLIENT_ID
        )

        # Extract user information
        user_info = {
            "email": idinfo.get("email"),
            "email_verified": idinfo.get("email_verified", False),
            "given_name": idinfo.get("given_name", ""),
            "family_name": idinfo.get("family_name", ""),
            "picture": idinfo.get("picture", ""),
            "sub": idinfo.get("sub"),  # Google user ID
        }

        # Security: Ensure email is verified
        if not user_info.get("email_verified"):
            logger.warning(
                f"validate_google_id_token: Unverified email: {user_info.get('email')}"
            )
            return None

        if not user_info.get("email"):
            logger.error("validate_google_id_token: Missing email in token")
            return None

        return user_info

    except ValueError as e:
        # Token validation failed
        logger.warning(f"validate_google_id_token: Validation failed - {str(e)}")
        return None

    except Exception as e:
        # Unexpected error
        logger.error(
            f"validate_google_id_token: Unexpected error - {str(e)}", exc_info=True
        )
        return None
