"""
OAuth 2.0 Authorization Server Views
Implements standard OAuth 2.0 authorization code flow for client applications
"""

from django.shortcuts import redirect, render
from django.http import JsonResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from urllib.parse import urlencode, urlparse, quote
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Application, AuthorizationCode, UserRole, RefreshToken
import logging
import json

logger = logging.getLogger(__name__)


def oauth_authorize(request):
    """
    OAuth 2.0 Authorization Endpoint

    GET /api/auth/authorize/?client_id=XXX&redirect_uri=YYY&response_type=code&scope=openid&state=ZZZ

    Flow:
    1. Validates client_id and redirect_uri
    2. Checks if user is authenticated (redirects to Google OAuth if not)
    3. Checks if user has access to this application
    4. Generates authorization code
    5. Redirects back to client with code and state
    """

    # Get OAuth parameters
    client_id = request.GET.get('client_id')
    redirect_uri = request.GET.get('redirect_uri')
    response_type = request.GET.get('response_type', 'code')
    scope = request.GET.get('scope', 'openid email profile')
    state = request.GET.get('state', '')

    logger.info(f"[FLOW AUTH 1] OAuth authorize: client={client_id[:10] if client_id else 'MISSING'}..., redirect_uri={redirect_uri}")

    # Validate required parameters
    if not client_id or not redirect_uri:
        logger.warning(f"[FLOW AUTH ERROR] Missing required parameters")
        return HttpResponseForbidden("Missing required parameters: client_id and redirect_uri")

    if response_type != 'code':
        logger.warning(f"[FLOW AUTH ERROR] Unsupported response_type: {response_type}")
        return HttpResponseForbidden("Only 'code' response_type is supported")

    # Validate client_id
    try:
        application = Application.objects.get(client_id=client_id, is_active=True)
        logger.info(f"[FLOW AUTH 2] Client validated: {application.name}")
    except Application.DoesNotExist:
        logger.error(f"[FLOW AUTH ERROR] Invalid client_id: {client_id}")
        return HttpResponseForbidden("Invalid client_id")

    # Validate redirect_uri matches registered URIs
    # Split on both commas and newlines to support both formats
    allowed_uris = [
        uri.strip()
        for line in application.redirect_uris.split('\n')
        for uri in line.split(',')
        if uri.strip()
    ]
    if redirect_uri not in allowed_uris:
        logger.error(f"[FLOW AUTH ERROR] Redirect URI mismatch. Got: {redirect_uri}, Allowed: {allowed_uris}")
        return HttpResponseForbidden("Invalid redirect_uri")

    # Try JWT authentication first (SSO uses JWT tokens)
    jwt_auth = JWTAuthentication()
    try:
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if auth_header.startswith('Bearer '):
            # Validate JWT token
            validated_token = jwt_auth.get_validated_token(auth_header.split(' ')[1])
            user = jwt_auth.get_user(validated_token)
            request.user = user
    except (AuthenticationFailed, Exception):
        # JWT auth failed, will check session auth below
        pass

    logger.info(f"[FLOW AUTH 3] User authenticated check: {request.user.is_authenticated}")

    # Check if user is authenticated
    if not request.user.is_authenticated:
        logger.info(f"[FLOW AUTH 4] User not authenticated, storing OAuth request and redirecting to Google OAuth")
        
        # Store OAuth request in session for later
        request.session['oauth_pending'] = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state,
        }
        request.session.modified = True
        
        # Redirect to Google OAuth
        return redirect('/api/auth/login/google/')

    # Check if user has access to this application
    try:
        user_role = UserRole.objects.get(
            user=request.user,
            application=application
        )
        logger.info(f"[FLOW AUTH 5] User has access to {application.name}")
    except UserRole.DoesNotExist:
        logger.warning(f"[FLOW AUTH ERROR] User {request.user.email} has no access to {application.name}")
        return HttpResponseForbidden(
            f"You don't have access to {application.name}. Contact your administrator."
        )

    # Generate authorization code
    auth_code = AuthorizationCode.objects.create(
        user=request.user,
        application=application,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state
    )

    logger.info(f"[FLOW AUTH 6] Generated auth code for {request.user.email} → {application.name}: {auth_code.code[:10]}...")

    # Redirect back to client with code and state
    params = {
        'code': auth_code.code,
        'state': state,
    }
    redirect_url = f"{redirect_uri}?{urlencode(params)}"
    logger.info(f"[FLOW AUTH 7] Redirecting to client: {redirect_url[:80]}...")
    return redirect(redirect_url)


@csrf_exempt
def oauth_token(request):
    """
    OAuth 2.0 Token Endpoint

    POST /api/auth/token/
    Body: {
        "code": "authorization_code",
        "client_id": "app_XXX",
        "client_secret": "secret",
        "redirect_uri": "http://...",
        "grant_type": "authorization_code"
    }

    Returns JWT access token and refresh token with user roles
    """

    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    logger.info(f"[FLOW TOKEN 1] Token exchange request received")

    # Get parameters (support both JSON and form data)
    if request.content_type == 'application/json':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            logger.warning(f"[FLOW TOKEN ERROR] Invalid JSON in request body")
            return JsonResponse({
                'error': 'invalid_request',
                'error_description': 'Invalid JSON in request body'
            }, status=400)
    else:
        data = request.POST

    code = data.get('code')
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    redirect_uri = data.get('redirect_uri')
    grant_type = data.get('grant_type')

    logger.info(f"[FLOW TOKEN 2] Token exchange: client={client_id[:10] if client_id else 'MISSING'}..., code={code[:10] if code else 'MISSING'}..., grant_type={grant_type}")

    # Validate required parameters
    if not all([code, client_id, client_secret, redirect_uri]):
        logger.warning(f"[FLOW TOKEN ERROR] Missing required parameters")
        return JsonResponse({
            'error': 'invalid_request',
            'error_description': 'Missing required parameters'
        }, status=400)

    if grant_type != 'authorization_code':
        logger.warning(f"[FLOW TOKEN ERROR] Unsupported grant_type: {grant_type}")
        return JsonResponse({
            'error': 'unsupported_grant_type',
            'error_description': 'Only authorization_code grant type is supported'
        }, status=400)

    # Validate client credentials
    try:
        application = Application.objects.get(
            client_id=client_id,
            client_secret=client_secret,
            is_active=True
        )
        logger.info(f"[FLOW TOKEN 3] Client validated: {application.name}")
    except Application.DoesNotExist:
        logger.error(f"[FLOW TOKEN ERROR] Invalid client credentials: {client_id}")
        return JsonResponse({
            'error': 'invalid_client',
            'error_description': 'Invalid client credentials'
        }, status=401)

    # Validate authorization code
    try:
        auth_code = AuthorizationCode.objects.get(
            code=code,
            application=application
        )
        logger.info(f"[FLOW TOKEN 4] Authorization code found: user={auth_code.user.email}")
    except AuthorizationCode.DoesNotExist:
        logger.error(f"[FLOW TOKEN ERROR] Invalid authorization code: {code}")
        return JsonResponse({
            'error': 'invalid_grant',
            'error_description': 'Invalid authorization code'
        }, status=400)

    # Check if code is valid (not expired, not used)
    if not auth_code.is_valid():
        logger.error(f"[FLOW TOKEN ERROR] Authorization code expired or already used: {code}")
        return JsonResponse({
            'error': 'invalid_grant',
            'error_description': 'Authorization code expired or already used'
        }, status=400)

    logger.info(f"[FLOW TOKEN 5] Authorization code valid")

    # Validate redirect_uri matches
    if auth_code.redirect_uri != redirect_uri:
        logger.error(f"[FLOW TOKEN ERROR] Redirect URI mismatch on token exchange")
        return JsonResponse({
            'error': 'invalid_grant',
            'error_description': 'Redirect URI mismatch'
        }, status=400)

    logger.info(f"[FLOW TOKEN 6] Redirect URI validated")

    # Mark code as used
    auth_code.used = True
    auth_code.save()

    logger.info(f"[FLOW TOKEN 7] Authorization code marked as used")

    # Get user's role for this application
    try:
        user_role = UserRole.objects.get(
            user=auth_code.user,
            application=application
        )
    except UserRole.DoesNotExist:
        logger.error(f"[FLOW TOKEN ERROR] User has no role in application")
        return JsonResponse({
            'error': 'invalid_grant',
            'error_description': 'User has no access to this application'
        }, status=400)

    # Generate tokens (reuse existing token generation logic)
    from .views import generate_token_response
    tokens = generate_token_response(auth_code.user)

    # Add role information to token response
    tokens['user']['roles'] = {
        application.slug: {
            'role': user_role.role,
            'permissions': user_role.permissions or {}
        }
    }

    logger.info(f"[FLOW TOKEN 8] Token exchange successful: {auth_code.user.email} → {application.name}")

    return JsonResponse(tokens)