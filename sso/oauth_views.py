import logging
import secrets

import requests
from decouple import config
from django.contrib.auth import authenticate
from django.shortcuts import redirect
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import User
from .tokens import CustomRefreshToken

try:
    from google.auth.transport import requests as google_requests
    from google.oauth2 import id_token

    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False

# Initialize logger
logger = logging.getLogger(__name__)

# Google OAuth settings
GOOGLE_CLIENT_ID = config("GOOGLE_CLIENT_ID", default="")


@api_view(["POST"])
@permission_classes([AllowAny])
def login_email(request):
    """Traditional email/password login"""
    email = request.data.get("email")
    password = request.data.get("password")

    if not email or not password:
        return Response(
            {"error": "Email and password required"}, status=status.HTTP_400_BAD_REQUEST
        )

    user = authenticate(username=email, password=password)
    if not user:
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )

    return generate_token_response(user)


@api_view(["GET", "POST"])
@permission_classes([AllowAny])
def login_google(request):
    """
    Google Sign-In authentication.

    GET: Initiates Google OAuth flow (redirects to Google consent screen)
    POST: Verifies Google ID token and creates/updates user
    """

    # Handle GET requests - initiate Google OAuth flow
    if request.method == "GET":
        logger.info("[GOOGLE LOGIN] GET request - initiating Google OAuth flow")

        if not GOOGLE_AUTH_AVAILABLE:
            return Response(
                {"error": "Google authentication not available"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        if not GOOGLE_CLIENT_ID:
            return Response(
                {"error": "Google OAuth not configured"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # GENERATE STATE TOKEN FOR CSRF PROTECTION AND SESSION CONTINUITY
        state = secrets.token_urlsafe(32)
        request.session["oauth_state"] = state
        logger.info(f"[GOOGLE LOGIN] Generated OAuth state token: {state[:10]}...")

        # STORE THE NEXT URL IN SESSION FOR AFTER CALLBACK
        next_url = request.GET.get("next")
        if next_url:
            request.session["oauth_next_url"] = next_url
            logger.info(f"[GOOGLE LOGIN] Stored next URL in session: {next_url}")

        # Save session immediately to ensure state is persisted
        request.session.save()

        # Build redirect URI (where Google will send user after authentication)
        # CRITICAL: Must match Google Console exactly (including trailing slash)
        redirect_uri = f"{request.scheme}://{request.get_host()}/auth/google/callback/"

        # Build Google OAuth authorization URL
        from urllib.parse import urlencode

        google_oauth_params = {
            "client_id": GOOGLE_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "prompt": "select_account",
            "state": state,  # Include state for CSRF protection
        }

        google_auth_url = (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            f"{urlencode(google_oauth_params)}"
        )

        logger.info(
            f"[GOOGLE LOGIN] Redirecting to Google OAuth: {google_auth_url[:80]}..."
        )

        # Redirect user to Google OAuth consent screen
        return redirect(google_auth_url)

    # Handle POST requests - verify ID token (for API/frontend use)
    token = request.data.get("token")

    if not token:
        return Response(
            {"error": "Google token required"}, status=status.HTTP_400_BAD_REQUEST
        )

    if not GOOGLE_AUTH_AVAILABLE:
        return Response(
            {"error": "Google authentication not available"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    if not GOOGLE_CLIENT_ID:
        return Response(
            {"error": "Google OAuth not configured"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    try:
        # Verify Google token
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        google_id = idinfo["sub"]
        email = idinfo["email"]
        name = idinfo.get("name", "")

        # Find or create user
        user, created = User.objects.get_or_create(
            google_id=google_id,
            defaults={
                "email": email,
                "username": email,  # Use email as username for Google users
                "display_name": name,
                "first_name": idinfo.get("given_name", ""),
                "last_name": idinfo.get("family_name", ""),
                "auth_type": "google",
                "is_active": True,
            },
        )

        # Update user info if existing
        if not created:
            user.email = email
            user.display_name = name
            user.first_name = idinfo.get("given_name", "")
            user.last_name = idinfo.get("family_name", "")
            user.save()

        return generate_token_response(user, created=created)

    except ValueError:
        return Response(
            {"error": "Invalid Google token"}, status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_anonymous(request):
    """Anonymous login with username and PIN"""
    username = request.data.get("username")
    pin = request.data.get("pin")

    if username and pin:
        # Existing anonymous user login
        try:
            user = User.objects.get(
                anonymous_username=username, pin_code=pin, is_anonymous=True
            )
            return generate_token_response(user)
        except User.DoesNotExist:
            return Response(
                {"error": "Invalid username or PIN"},
                status=status.HTTP_401_UNAUTHORIZED,
            )
    else:
        # Create new anonymous user
        user = User.objects.create(
            auth_type="anonymous",
            is_anonymous=True,
            is_active=True,
        )

        # Save to generate username and PIN
        user.save()

        return generate_token_response(
            user,
            anonymous_credentials={
                "username": user.anonymous_username,
                "pin": user.pin_code,
            },
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def register_email(request):
    """Register new email/password user"""
    email = request.data.get("email")
    password = request.data.get("password")
    display_name = request.data.get("display_name", "")
    first_name = request.data.get("first_name", "")
    last_name = request.data.get("last_name", "")

    if not email or not password:
        return Response(
            {"error": "Email and password required"}, status=status.HTTP_400_BAD_REQUEST
        )

    if User.objects.filter(email=email).exists():
        return Response(
            {"error": "Email already registered"}, status=status.HTTP_400_BAD_REQUEST
        )

    user = User.objects.create_user(
        username=email,
        email=email,
        password=password,
        display_name=display_name,
        first_name=first_name,
        last_name=last_name,
        auth_type="email",
    )

    return generate_token_response(user, created=True)


def generate_token_response(user, created=False, anonymous_credentials=None):
    """Generate JWT token response"""
    refresh = CustomRefreshToken.for_user(user)

    # Get user roles
    roles = {}
    for role in user.roles.select_related("application").all():
        if role.application.slug:
            roles[role.application.slug] = {
                "app_slug": role.application.slug,
                "app_name": role.application.name,
                "role": role.role,
                "permissions": role.permissions,
            }

    response_data = {
        "access_token": str(refresh.access_token),
        "refresh_token": str(refresh),
        "user": {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "display_identifier": user.display_identifier,
            "auth_type": user.auth_type,
            "is_anonymous": user.is_anonymous,
            "is_sso_admin": user.is_sso_admin,
            "roles": roles,
        },
    }

    # Include anonymous credentials for new anonymous users
    if anonymous_credentials:
        response_data["anonymous_credentials"] = anonymous_credentials
        response_data["message"] = (
            "Anonymous account created. Save your username and PIN!"
        )

    if created and not anonymous_credentials:
        response_data["message"] = "Account created successfully"

    return Response(response_data)


@api_view(["GET"])
@permission_classes([AllowAny])
def google_auth_callback(request):
    """Handle Google OAuth redirect callback"""

    logger.info("[GOOGLE CALLBACK] Callback received")

    # VERIFY STATE PARAMETER FOR CSRF PROTECTION
    state = request.GET.get("state")
    stored_state = request.session.get("oauth_state")

    if not state:
        logger.error("[GOOGLE CALLBACK] No state parameter in callback URL")
        return Response(
            {"error": "No session ID provided in URL"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if not stored_state:
        logger.error("[GOOGLE CALLBACK] No stored state in session")
        return Response(
            {"error": "Session expired or invalid"}, status=status.HTTP_400_BAD_REQUEST
        )

    if state != stored_state:
        logger.error(
            "[GOOGLE CALLBACK] State mismatch - possible CSRF attack. "
            f"Expected: {stored_state[:10]}..., Got: {state[:10]}..."
        )
        return Response(
            {"error": "Invalid session state - possible CSRF attack"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    logger.info(f"[GOOGLE CALLBACK] State verified successfully: {state[:10]}...")

    # Clear the state from session after successful verification
    request.session.pop("oauth_state", None)

    # Get the authorization code from the callback
    code = request.GET.get("code")
    if not code:
        logger.error("[GOOGLE CALLBACK] No authorization code in callback")
        return Response(
            {"error": "Authorization code not provided"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    logger.info(f"[GOOGLE CALLBACK] Authorization code received: {code[:20]}...")

    # Exchange the code for tokens
    # CRITICAL: Must match the redirect_uri sent to Google in authorization request
    redirect_uri = f"{request.scheme}://{request.get_host()}/auth/google/callback/"
    token_url = "https://oauth2.googleapis.com/token"

    payload = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": config("GOOGLE_CLIENT_SECRET", default=""),
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    try:
        response = requests.post(token_url, data=payload, timeout=10)
        response.raise_for_status()
    except requests.Timeout:
        logger.error("[GOOGLE CALLBACK] Token exchange request timed out")
        return Response(
            {
                "error": "Authentication service temporarily unavailable. Please try again."
            },
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    except requests.HTTPError:
        logger.error(
            f"[GOOGLE CALLBACK] Token exchange failed: HTTP {response.status_code}",
            extra={
                "status_code": response.status_code,
                "response_text": response.text[:200],
            },
        )
        return Response(
            {
                "error": "Failed to exchange authorization code for tokens",
                "details": (
                    "Authentication failed. Please try again or contact support."
                ),
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    except requests.RequestException:
        logger.error("[GOOGLE CALLBACK] Token exchange network error")
        return Response(
            {"error": "Network error during authentication. Please try again."},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    # Extract tokens from response
    token_data = response.json()
    id_token_value = token_data.get("id_token")

    if not id_token_value:
        return Response(
            {"error": "No ID token in response"}, status=status.HTTP_400_BAD_REQUEST
        )

    # Verify the ID token
    try:
        idinfo = id_token.verify_oauth2_token(
            id_token_value, google_requests.Request(), GOOGLE_CLIENT_ID
        )

        google_id = idinfo["sub"]
        email = idinfo["email"]
        name = idinfo.get("name", "")

        # Find or create user
        user, created = User.objects.get_or_create(
            google_id=google_id,
            defaults={
                "email": email,
                "username": email,  # Use email as username for Google users
                "display_name": name,
                "first_name": idinfo.get("given_name", ""),
                "last_name": idinfo.get("family_name", ""),
                "auth_type": "google",
                "is_active": True,
            },
        )

        # Update user info if existing
        if not created:
            user.email = email
            user.display_name = name
            user.first_name = idinfo.get("given_name", "")
            user.last_name = idinfo.get("family_name", "")
            user.save()

        # CHECK IF THIS IS AN ADMIN LOGIN (has next URL in session)
        next_url = request.session.pop("oauth_next_url", None)

        if next_url and "/cbrt-ops/" in next_url:
            # This is admin login - use Django's built-in auth
            from django.contrib.auth import login as django_login

            # Mark user as staff/superuser if they're SSO admin
            if user.is_sso_admin:
                user.is_staff = True
                user.is_superuser = True
                user.save()

            # Log them into Django admin
            django_login(request, user)
            logger.info(
                "[GOOGLE CALLBACK] Admin login successful for "
                f"{user.email}, redirecting to {next_url}"
            )
            return redirect(next_url)

        # Regular API login - return tokens
        refresh = CustomRefreshToken.for_user(user)

        # Redirect to success page with tokens (or use next_url if provided)
        if next_url:
            # Add tokens to the redirect URL if it's not admin
            from urllib.parse import urlencode

            params = {
                "access_token": str(refresh.access_token),
                "refresh_token": str(refresh),
            }
            separator = "&" if "?" in next_url else "?"
            return redirect(f"{next_url}{separator}{urlencode(params)}")
        else:
            # Default success page
            access = str(refresh.access_token)
            refresh_str = str(refresh)
            success_url = (
                f"/login/google-success/?access_token={access}"
                f"&refresh_token={refresh_str}"
            )
            return redirect(success_url)

    except ValueError as e:
        logger.error(f"[GOOGLE CALLBACK] Token verification failed: {str(e)}")
        return Response(
            {"error": "Invalid Google token", "details": str(e)},
            status=status.HTTP_400_BAD_REQUEST,
        )
