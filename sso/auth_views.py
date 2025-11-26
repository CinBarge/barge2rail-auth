import logging
import secrets

import requests
from decouple import config
from django.contrib.auth import authenticate, login
from django.contrib.sessions.models import Session
from django.shortcuts import redirect
from django_ratelimit.decorators import ratelimit
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from .models import User
from .tokens import CustomRefreshToken
from .views import is_account_locked, log_login_attempt

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
@ratelimit(key="ip", rate="5/1h", method="POST", block=True)
def login_email(request):
    """Traditional email/password login with OAuth flow support"""
    email = request.data.get("email")
    password = request.data.get("password")
    next_url = request.data.get("next")  # Extract next parameter from POST data

    if not email or not password:
        return Response(
            {"error": "Email and password required"}, status=status.HTTP_400_BAD_REQUEST
        )

    # Get client IP address
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        ip_address = x_forwarded_for.split(",")[0]
    else:
        ip_address = request.META.get("REMOTE_ADDR")

    # Check if account is locked
    if is_account_locked(email):
        log_login_attempt(email, ip_address, success=False)
        return Response(
            {
                "error": "Account temporarily locked due to too many failed attempts. Try again in 15 minutes."
            },
            status=status.HTTP_403_FORBIDDEN,
        )

    user = authenticate(username=email, password=password)
    if not user:
        log_login_attempt(email, ip_address, success=False)
        return Response(
            {"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED
        )

    # CRITICAL: Create Django session for OAuth flow
    # Without this, no session cookie is set and /o/authorize/ fails
    logger.info(
        f"[EMAIL LOGIN] User {email} authenticated. "
        f"Session key BEFORE login: {request.session.session_key}"
    )

    # Login creates Django session (required for OAuth authorize endpoint)
    login(request, user)

    # Log successful login attempt
    log_login_attempt(email, ip_address, success=True)

    # Force session save to ensure cookie is set
    request.session.save()

    logger.info(
        f"[EMAIL LOGIN] Session created. "
        f"Session key AFTER login: {request.session.session_key}, "
        f"Modified: {request.session.modified}"
    )

    # Verify session exists in database
    session_exists = Session.objects.filter(
        session_key=request.session.session_key
    ).exists()
    logger.info(f"[EMAIL LOGIN] Session exists in DB: {session_exists}")

    # Pass next_url to token response for OAuth flow continuity
    response = generate_token_response(user, next_url=next_url)

    # CRITICAL FIX: DRF Response doesn't automatically include session cookies
    # We must manually set the session cookie on the response
    from django.conf import settings

    cookie_domain = getattr(settings, "SESSION_COOKIE_DOMAIN", None)
    cookie_name = settings.SESSION_COOKIE_NAME
    cookie_age = settings.SESSION_COOKIE_AGE
    cookie_secure = settings.SESSION_COOKIE_SECURE
    cookie_httponly = settings.SESSION_COOKIE_HTTPONLY
    cookie_samesite = settings.SESSION_COOKIE_SAMESITE

    # Set session cookie on DRF response
    response.set_cookie(
        key=cookie_name,
        value=request.session.session_key,
        max_age=cookie_age,
        domain=cookie_domain,
        secure=cookie_secure,
        httponly=cookie_httponly,
        samesite=cookie_samesite,
    )

    logger.info(
        f"[EMAIL LOGIN] Session cookie set on response - "
        f"DOMAIN: {cookie_domain or 'current domain'}, "
        f"SAMESITE: {cookie_samesite}, "
        f"SECURE: {cookie_secure}, "
        f"MAX_AGE: {cookie_age}s"
    )

    # Check response cookies (DRF Response has cookies attribute)
    if hasattr(response, "cookies") and cookie_name in response.cookies:
        cookie = response.cookies[cookie_name]
        logger.info(
            f"[EMAIL LOGIN] Cookie confirmed in response.cookies: "
            f"{cookie_name}={cookie.value[:20]}... "
            f"(domain={cookie['domain']}, samesite={cookie['samesite']})"
        )
    else:
        available_cookies = (
            list(response.cookies.keys()) if hasattr(response, "cookies") else "N/A"
        )
        logger.error(
            f"[EMAIL LOGIN] Cookie NOT in response.cookies! "
            f"Available: {available_cookies}"
        )

    return response


@api_view(["GET", "POST"])
@permission_classes([AllowAny])
@ratelimit(key="ip", rate="20/1h", method="POST", block=True)
def login_google(request):
    """
    Google Sign-In authentication.

    GET: Initiates Google OAuth flow (redirects to Google consent screen)
    POST: Verifies Google ID token and creates/updates user

    Rate limit: 20 POST requests per hour per IP
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

    # Handle POST requests - verify ID token
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
@ratelimit(key="ip", rate="10/1h", method="POST", block=True)
def login_anonymous(request):
    """Anonymous login with username and PIN.

    Security: PIN is hashed on storage, verified using check_pin().
    """
    username = request.data.get("username")
    pin = request.data.get("pin")

    if username and pin:
        # Existing anonymous user login
        try:
            user = User.objects.get(anonymous_username=username, is_anonymous=True)
            # Use check_pin() to verify hashed PIN
            if user.check_pin(pin):
                return generate_token_response(user)
            else:
                return Response(
                    {"error": "Invalid username or PIN"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
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

        # Save to generate username and PIN (hashed)
        user.save()

        # Return plaintext PIN only on creation (stored in _plaintext_pin)
        return generate_token_response(
            user,
            anonymous_credentials={
                "username": user.anonymous_username,
                "pin": user._plaintext_pin,  # Plaintext only available at creation
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


def generate_token_response(
    user, created=False, anonymous_credentials=None, next_url=None
):
    """Generate JWT token response with optional OAuth flow redirect URL"""
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

    # Include next_url for OAuth flow continuity (e.g., redirect to /o/authorize/)
    if next_url:
        response_data["next_url"] = next_url
        logger.info(f"Including next_url in response: {next_url}")

    # Include anonymous credentials for new anonymous users
    if anonymous_credentials:
        response_data["user"]["anonymous_credentials"] = anonymous_credentials
        response_data["message"] = (
            "Anonymous account created. Save your username and PIN!"
        )

    if created and not anonymous_credentials:
        response_data["message"] = "Account created successfully"

    return Response(response_data)


@api_view(["GET"])
@permission_classes([AllowAny])
def debug_google_config(request):
    """Debug endpoint to verify Google OAuth configuration.

    Security: Disabled in production (only available when DEBUG=True).
    """
    from django.conf import settings

    # Security: Block debug endpoint in production
    if not settings.DEBUG:
        return Response(
            {"error": "Debug endpoint disabled in production"},
            status=status.HTTP_403_FORBIDDEN,
        )

    return Response(
        {
            "client_id_from_decouple": GOOGLE_CLIENT_ID,
            "client_id_from_settings": getattr(settings, "GOOGLE_CLIENT_ID", "NOT SET"),
            "google_auth_available": GOOGLE_AUTH_AVAILABLE,
            "current_origin": f"{request.scheme}://{request.get_host()}",
            "request_meta_host": request.headers.get("host"),
            "debug_info": {
                "scheme": request.scheme,
                "host": request.get_host(),
                "path": request.path,
                "full_url": request.build_absolute_uri(),
            },
        }
    )


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
                "error": (
                    "Authentication service temporarily unavailable. "
                    "Please try again."
                )
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
        from datetime import timedelta

        from django.utils import timezone

        from .models import TokenExchangeSession

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

        # Generate tokens for the user
        refresh = CustomRefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        # SECURITY FIX: Use TokenExchangeSession instead of URL params
        # Tokens are never exposed in URL - only session ID is passed
        exchange_session = TokenExchangeSession.objects.create(
            access_token=access_token,
            refresh_token=refresh_token,
            user_email=email,
            expires_at=timezone.now() + timedelta(seconds=60),  # 60 second expiry
        )

        logger.info(
            f"[GOOGLE CALLBACK] Created token exchange session "
            f"{exchange_session.session_id} for {email}"
        )

        # Redirect with only session_id - frontend exchanges for tokens via API
        success_url = f"/login/google-success/?session_id={exchange_session.session_id}"
        return redirect(success_url)

    except ValueError as e:
        return Response(
            {"error": "Invalid Google token", "details": str(e)},
            status=status.HTTP_400_BAD_REQUEST,
        )
