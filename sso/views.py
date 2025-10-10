import requests
import logging
import secrets
import time
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
from django.db import transaction
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from sso.tokens import CustomRefreshToken
from django.contrib.auth import authenticate, login
from django_ratelimit.decorators import ratelimit
from .models import User, Application, UserRole
from .serializers import (
    UserSerializer, UserRegistrationSerializer, LoginSerializer,
    ApplicationSerializer, UserRoleSerializer
)

logger = logging.getLogger(__name__)
security_logger = logging.getLogger('django.security')

# ============================================================================
# OAuth State Parameter Helpers (Gate 5: CSRF Protection)
# ============================================================================

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


def validate_oauth_state(state_from_callback, state_from_session, timeout=60):
    """
    Validate OAuth state parameter for CSRF protection.

    Args:
        state_from_callback (str): State parameter from OAuth callback
        state_from_session (str): State stored in session during initiation
        timeout (int): Maximum age in seconds (default 60 seconds)

    Returns:
        bool: True if valid, False otherwise
    """
    if not state_from_callback or not state_from_session:
        security_logger.warning("OAuth state validation failed: Missing state parameter")
        return False

    if state_from_callback != state_from_session:
        security_logger.warning(
            f"OAuth state validation failed: State mismatch "
            f"(callback: {state_from_callback[:10]}..., session: {state_from_session[:10]}...)"
        )
        return False

    # Check timestamp to prevent replay attacks
    try:
        _, timestamp_str = state_from_session.split(':')
        timestamp = int(timestamp_str)
        age = int(time.time()) - timestamp
        if age > timeout:
            security_logger.warning(f"OAuth state validation failed: State expired (age: {age}s)")
            return False
    except (ValueError, AttributeError) as e:
        security_logger.warning(f"OAuth state validation failed: Invalid format - {e}")
        return False

    return True


# ============================================================================
# Account Lockout Helpers (HIGH-2)
# ============================================================================

def check_account_lockout(identifier, request):
    """
    Check if account is locked out due to failed login attempts.

    Args:
        identifier (str): Email or anonymous_username
        request: Django request object

    Returns:
        tuple: (is_locked, Response or None)
            - is_locked (bool): True if account is locked
            - Response: Error response if locked, None otherwise
    """
    from .models import LoginAttempt
    from django.utils import timezone
    from datetime import timedelta
    from django.conf import settings

    # Skip lockout check if rate limiting is disabled (e.g., in DEBUG mode)
    if not getattr(settings, 'RATELIMIT_ENABLE', True):
        return False, None

    # Check failed attempts in last 15 minutes
    lockout_window = timezone.now() - timedelta(minutes=15)
    recent_failures = LoginAttempt.objects.filter(
        identifier=identifier,
        success=False,
        attempted_at__gte=lockout_window
    ).count()

    if recent_failures >= 5:
        security_logger.warning(
            f"Account lockout triggered for {identifier} from {request.META.get('REMOTE_ADDR')} "
            f"({recent_failures} failed attempts)"
        )
        return True, Response(
            {
                'error': 'Account temporarily locked due to multiple failed login attempts. '
                        'Please try again in 15 minutes.'
            },
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    return False, None


def log_login_attempt(identifier, ip_address, success):
    """
    Log a login attempt for security tracking.

    Args:
        identifier (str): Email or anonymous_username
        ip_address (str): IP address of attempt
        success (bool): True if login succeeded
    """
    from .models import LoginAttempt

    LoginAttempt.objects.create(
        identifier=identifier,
        ip_address=ip_address,
        success=success
    )

    if success:
        logger.info(f"Successful login for {identifier} from {ip_address}")
    else:
        security_logger.warning(f"Failed login attempt for {identifier} from {ip_address}")


# ============================================================================
# OAuth Error Messages
# ============================================================================

OAUTH_ERROR_MESSAGES = {
    'invalid_state': "Authentication failed: Invalid or expired request. Please try again.",
    'missing_code': "Authentication failed: No authorization code received.",
    'token_error': "Authentication failed: Could not obtain access token.",
    'user_info_error': "Authentication failed: Could not retrieve user information.",
}

# ============================================================================
# Admin Google OAuth Views (Server-side redirect flow)
# ============================================================================

def admin_google_login(request):
    """
    Initiate Google OAuth for Django admin login (GET redirect flow)
    """
    from django.shortcuts import redirect
    from urllib.parse import urlencode

    # Store next parameter and generate state
    next_url = request.GET.get('next', '/admin/')
    state = generate_oauth_state()
    request.session['oauth_state'] = state
    request.session['oauth_next'] = next_url
    request.session.modified = True

    # Build Google OAuth URL
    redirect_uri = f'{settings.BASE_URL}/auth/admin/google/callback/'
    params = {
        'client_id': settings.GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'response_type': 'code',
        'access_type': 'offline',
        'prompt': 'select_account',
        'state': state
    }

    auth_url = f'https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}'
    return redirect(auth_url)


def admin_google_callback(request):
    """
    Handle Google OAuth callback for admin login (GET redirect flow)
    """
    from django.shortcuts import redirect
    from django.http import HttpResponse

    # Get code and state from query parameters
    code = request.GET.get('code')
    state_from_callback = request.GET.get('state')
    error = request.GET.get('error')

    # Handle OAuth errors (user cancelled, etc.)
    if error:
        logger.warning(f"Google OAuth error: {error}")
        return HttpResponse(f"Authentication cancelled: {error}", status=400)

    # Validate state
    state_from_session = request.session.get('oauth_state')
    if not validate_oauth_state(state_from_callback, state_from_session):
        security_logger.warning(
            f"OAuth state validation failed for admin login - "
            f"IP: {request.META.get('REMOTE_ADDR')}"
        )
        return HttpResponse("Authentication failed: Invalid or expired request", status=403)

    # Get next URL BEFORE clearing session (login() will create new session)
    next_url = request.session.get('oauth_next', '/admin/')

    if not code:
        return HttpResponse("Authentication failed: No authorization code received", status=400)

    try:
        # Exchange code for tokens (reuse existing function but with admin callback URI)
        token_url = 'https://oauth2.googleapis.com/token'
        redirect_uri = f'{settings.BASE_URL}/auth/admin/google/callback/'

        data = {
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri
        }

        response = requests.post(token_url, data=data, timeout=10)
        token_data = response.json()

        if response.status_code != 200:
            logger.error(f'Admin OAuth token exchange failed: {token_data}')
            return HttpResponse(f"Authentication failed: {token_data.get('error_description', 'Could not obtain access token')}", status=400)

        # Verify ID token and get user info
        user_info = verify_google_id_token(token_data['id_token'])

        # Create or get user
        user, created = get_or_create_google_user(user_info)

        # Log user into Django session (this creates a NEW session, invalidating the old one)
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        logger.info(f"Admin login successful for {user.email}")

        # Redirect to admin or next URL
        return redirect(next_url)

    except Exception as e:
        logger.error(f"Admin OAuth callback error: {e}")
        return HttpResponse(f"Authentication failed: {str(e)}", status=500)


@ratelimit(key='ip', rate='20/h', method='POST', block=False)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_google_oauth(request):
    """
    Handle Google OAuth code exchange with state validation.
    Gate 5: OAuth State Parameter CSRF Protection
    """
    # Check if rate limited
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        security_logger.warning(
            f"Rate limit exceeded for OAuth login from {request.META.get('REMOTE_ADDR')}"
        )
        return Response(
            {'error': 'Too many login attempts. Please try again later.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    code = request.data.get('code')
    state_from_callback = request.data.get('state')

    # Gate 5: Validate state parameter
    state_from_session = request.session.get('oauth_state')

    if not validate_oauth_state(state_from_callback, state_from_session):
        security_logger.warning(
            f"OAuth state validation failed - "
            f"IP: {request.META.get('REMOTE_ADDR')}, "
            f"User-Agent: {request.META.get('HTTP_USER_AGENT')}"
        )
        return Response({'error': OAUTH_ERROR_MESSAGES['invalid_state']}, status=403)

    # Gate 5: Clear state from session (one-time use)
    if 'oauth_state' in request.session:
        del request.session['oauth_state']
        request.session.modified = True

    # Validate authorization code
    if not code:
        return Response({'error': OAUTH_ERROR_MESSAGES['missing_code']}, status=400)

    try:
        # Exchange code for tokens
        token_data = exchange_google_code_for_tokens(code)

        if 'error' in token_data:
            logger.error(f'Google token exchange error: {token_data}')
            return Response({'error': token_data.get('error_description', OAUTH_ERROR_MESSAGES['token_error'])}, status=400)

        # Verify ID token and get user info
        user_info = verify_google_id_token(token_data['id_token'])

        # Create or get user
        user, created = get_or_create_google_user(user_info)

        # Log user into Django session (needed for OAuth authorization endpoint)
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        # Generate JWT tokens
        response_data = generate_token_response(user, created=created)

        if created:
            logger.info(f'New Google user created: {user.email}')
        else:
            logger.info(f'Existing Google user signed in: {user.email}')

        return Response(response_data)

    except Exception as e:
        logger.error(f'Google OAuth error: {str(e)}')
        return Response({'error': OAUTH_ERROR_MESSAGES['user_info_error']}, status=400)

def exchange_google_code_for_tokens(code):
    """Exchange authorization code for access/ID tokens"""
    token_url = 'https://oauth2.googleapis.com/token'

    redirect_uri = f'{settings.BASE_URL}/auth/google/callback/'
    
    data = {
        'client_id': settings.GOOGLE_CLIENT_ID,
        'client_secret': settings.GOOGLE_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri
    }
    
    logger.info(f'Exchanging code for tokens with redirect_uri: {redirect_uri}')
    
    try:
        response = requests.post(token_url, data=data, timeout=10)
        token_data = response.json()
        
        if response.status_code != 200:
            logger.error(f'Token exchange failed: {token_data}')
            
        return token_data
    except requests.RequestException as e:
        logger.error(f'Token exchange request failed: {e}')
        return {'error': 'network_error', 'error_description': 'Failed to contact Google'}

def verify_google_id_token(id_token_str):
    """Verify Google ID token and extract user info"""
    try:
        # Verify the token
        idinfo = id_token.verify_oauth2_token(
            id_token_str, 
            google_requests.Request(), 
            settings.GOOGLE_CLIENT_ID
        )
        
        # Check issuer
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        
        return {
            'google_id': idinfo['sub'],
            'email': idinfo['email'],
            'name': idinfo.get('name', ''),
            'picture': idinfo.get('picture', ''),
            'email_verified': idinfo.get('email_verified', False)
        }
    except ValueError as e:
        logger.error(f'Invalid Google ID token: {e}')
        raise Exception(f'Invalid token: {e}')

@transaction.atomic
def get_or_create_google_user(user_info):
    """Get or create user from Google info.
    
    DATA SAFETY: All database operations wrapped in transaction.
    If any operation fails, entire transaction rolls back.
    Prevents partial user records and data corruption.
    """
    try:
        # Try to find existing user by Google ID
        user = User.objects.get(google_id=user_info['google_id'])

        # Update user info - ONLY save fields we're actually changing
        # This prevents overwriting permissions set via admin/shell
        fields_to_update = []

        if user.email != user_info['email']:
            user.email = user_info['email']
            fields_to_update.append('email')

        if user.display_name != user_info['name']:
            user.display_name = user_info['name']
            fields_to_update.append('display_name')

        if not user.is_active:
            user.is_active = True
            fields_to_update.append('is_active')

        # Only save if something actually changed
        if fields_to_update:
            user.save(update_fields=fields_to_update)
            logger.info(f'Updated existing Google user: {user.email} (fields: {fields_to_update})')
        else:
            logger.info(f'No updates needed for Google user: {user.email}')

        return user, False
        
    except User.DoesNotExist:
        # Check if email already exists with different auth method
        existing_user = User.objects.filter(email=user_info['email']).first()
        if existing_user:
            # Link Google account to existing user
            # ONLY update the fields needed for Google linking
            existing_user.google_id = user_info['google_id']
            existing_user.auth_type = 'google'
            existing_user.save(update_fields=['google_id', 'auth_type'])
            logger.info(f'Linked Google account to existing user: {existing_user.email}')
            return existing_user, False
        
        # Create new user
        user = User.objects.create(
            email=user_info['email'],
            display_name=user_info['name'] or user_info['email'],
            google_id=user_info['google_id'],
            auth_type='google',
            is_active=True,
            username=user_info['email']  # Use email as username
        )
        
        logger.info(f'Created new Google user: {user.email}')
        return user, True

@ratelimit(key='ip', rate='5/h', method='POST', block=False)
@api_view(['POST'])
@permission_classes([AllowAny])
def login_email(request):
    """Traditional email/password login with account lockout protection"""
    # Check if rate limited
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        security_logger.warning(
            f"Rate limit exceeded for email login from {request.META.get('REMOTE_ADDR')}"
        )
        return Response(
            {'error': 'Too many login attempts. Please try again later.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response({'error': 'Email and password required'},
                       status=status.HTTP_400_BAD_REQUEST)

    # HIGH-2: Check for account lockout
    is_locked, lockout_response = check_account_lockout(email, request)
    if is_locked:
        return lockout_response

    # Attempt authentication
    user = authenticate(username=email, password=password)
    ip_address = request.META.get('REMOTE_ADDR', 'unknown')

    if not user:
        # HIGH-2: Log failed attempt
        log_login_attempt(email, ip_address, success=False)
        return Response({'error': 'Invalid credentials'},
                       status=status.HTTP_401_UNAUTHORIZED)

    # HIGH-2: Log successful attempt
    log_login_attempt(email, ip_address, success=True)
    return Response(generate_token_response(user))

@ratelimit(key='ip', rate='10/h', method='POST', block=False)
@api_view(['POST'])
@permission_classes([AllowAny])
@transaction.atomic
def login_anonymous(request):
    """Anonymous login with username and PIN with account lockout protection.

    DATA SAFETY: User creation wrapped in transaction.
    """
    # Check if rate limited
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        security_logger.warning(
            f"Rate limit exceeded for anonymous login from {request.META.get('REMOTE_ADDR')}"
        )
        return Response(
            {'error': 'Too many login attempts. Please try again later.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    username = request.data.get('username')
    pin = request.data.get('pin')
    ip_address = request.META.get('REMOTE_ADDR', 'unknown')

    if username and pin:
        # Existing anonymous user login
        # HIGH-2: Check for account lockout
        is_locked, lockout_response = check_account_lockout(username, request)
        if is_locked:
            return lockout_response

        try:
            user = User.objects.get(
                anonymous_username=username,
                pin_code=pin,
                is_anonymous=True
            )
            # HIGH-2: Log successful attempt
            log_login_attempt(username, ip_address, success=True)
            return Response(generate_token_response(user))
        except User.DoesNotExist:
            # HIGH-2: Log failed attempt
            log_login_attempt(username, ip_address, success=False)
            return Response({'error': 'Invalid username or PIN'},
                           status=status.HTTP_401_UNAUTHORIZED)
    else:
        # Create new anonymous user
        user = User.objects.create(
            auth_type='anonymous',
            is_anonymous=True,
            is_active=True,
        )

        # Save to generate username and PIN
        user.save()

        return Response(generate_token_response(user, anonymous_credentials={
            'username': user.anonymous_username,
            'pin': user.pin_code
        }))

@api_view(['POST'])
@permission_classes([AllowAny])
@transaction.atomic
def register_email(request):
    """Register new email/password user.
    
    DATA SAFETY: User creation wrapped in transaction.
    """
    email = request.data.get('email')
    password = request.data.get('password')
    display_name = request.data.get('display_name', '')
    first_name = request.data.get('first_name', '')
    last_name = request.data.get('last_name', '')
    
    if not email or not password:
        return Response({'error': 'Email and password required'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    if User.objects.filter(email=email).exists():
        return Response({'error': 'Email already registered'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    user = User.objects.create_user(
        username=email,
        email=email,
        password=password,
        display_name=display_name,
        first_name=first_name,
        last_name=last_name,
        auth_type='email'
    )

    return Response(generate_token_response(user, created=True))

@api_view(['GET'])
@permission_classes([AllowAny])
def google_oauth_url(request):
    """
    Generate Google OAuth URL with state parameter for CSRF protection.
    Gate 5: OAuth State Parameter Implementation
    """
    redirect_uri = f'{settings.BASE_URL}/auth/google/callback/'

    # Gate 5: Generate and store state parameter
    state = generate_oauth_state()
    request.session['oauth_state'] = state
    request.session.modified = True

    params = {
        'client_id': settings.GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'response_type': 'code',
        'access_type': 'offline',
        'prompt': 'select_account',
        'state': state  # Gate 5: Include state in OAuth URL
    }

    from urllib.parse import urlencode
    auth_url = f'https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}'

    logger.info(f"Generated OAuth URL with state parameter (length: {len(state)})")

    return Response({
        'auth_url': auth_url,
        'redirect_uri': redirect_uri,
        'client_id': settings.GOOGLE_CLIENT_ID
    })

@api_view(['GET'])
@permission_classes([AllowAny])
def google_config_check(request):
    """Check Google OAuth configuration"""
    config_status = {
        'google_client_id': bool(settings.GOOGLE_CLIENT_ID),
        'google_client_secret': bool(settings.GOOGLE_CLIENT_SECRET),
        'base_url': settings.BASE_URL,
        'redirect_uri': f'{settings.BASE_URL}/auth/google/callback/'
    }
    
    # Check if all required settings are present
    all_configured = all([
        settings.GOOGLE_CLIENT_ID,
        settings.GOOGLE_CLIENT_SECRET,
        settings.BASE_URL
    ])
    
    config_status['fully_configured'] = all_configured

    return Response(config_status)

@api_view(['GET'])
@permission_classes([AllowAny])
def exchange_session_for_tokens(request, session_id):
    """
    Exchange a TokenExchangeSession ID for access/refresh tokens.

    This endpoint provides secure token retrieval after OAuth callback.
    Tokens are never exposed in URLs - only the session ID is passed.

    Security features:
    - Single-use sessions (marked as used after first retrieval)
    - 60-second expiry window
    - Returns 404 for used or expired sessions
    - Automatic cleanup of expired sessions
    """
    from .models import TokenExchangeSession
    from django.utils import timezone

    # CRITICAL-3: Delete ALL expired sessions on every exchange attempt
    expired_count = TokenExchangeSession.objects.filter(
        expires_at__lt=timezone.now()
    ).delete()[0]
    if expired_count > 0:
        logger.info(f"Cleaned up {expired_count} expired token exchange sessions")

    try:
        # Fetch the session
        session = TokenExchangeSession.objects.get(session_id=session_id)

        # Check if already used
        if session.used:
            logger.warning(f"Attempt to reuse token exchange session: {session_id}")
            return Response(
                {'error': 'Session already used'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Check if expired
        if timezone.now() > session.expires_at:
            logger.warning(f"Attempt to use expired token exchange session: {session_id}")
            session.delete()  # Cleanup expired session
            return Response(
                {'error': 'Session expired'},
                status=status.HTTP_404_NOT_FOUND
            )

        # Mark session as used
        session.used = True
        session.save()

        # Get user for additional info
        try:
            user = User.objects.get(email=session.user_email)
            user_data = {
                'id': str(user.id),
                'email': user.email,
                'display_name': user.display_name,
                'auth_type': user.auth_type,
                'is_sso_admin': user.is_sso_admin,
            }
        except User.DoesNotExist:
            user_data = {'email': session.user_email}

        logger.info(f"Token exchange successful for session {session_id} - user: {session.user_email}")

        # Return tokens
        return Response({
            'access_token': session.access_token,
            'refresh_token': session.refresh_token,
            'user': user_data
        })

    except TokenExchangeSession.DoesNotExist:
        logger.warning(f"Invalid token exchange session requested: {session_id}")
        return Response(
            {'error': 'Invalid session'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error exchanging session {session_id} for tokens: {str(e)}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

def generate_token_response(user, created=False, anonymous_credentials=None):
    """Generate JWT token response"""
    refresh = CustomRefreshToken.for_user(user)
    
    # Get user roles
    roles = {}
    for role in user.roles.select_related('application').all():
        if role.application.slug:
            roles[role.application.slug] = {
                'app_slug': role.application.slug,
                'app_name': role.application.name,
                'role': role.role,
                'permissions': role.permissions
            }
    
    response_data = {
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh),
        'user': {
            'id': str(user.id),
            'email': user.email,
            'display_name': user.display_name,
            'display_identifier': user.display_identifier,
            'auth_type': user.auth_type,
            'is_anonymous': user.is_anonymous,
            'is_sso_admin': user.is_sso_admin,
            'roles': roles
        }
    }

    # Include anonymous credentials for new anonymous users
    if anonymous_credentials:
        response_data['user']['anonymous_credentials'] = anonymous_credentials
        response_data['message'] = 'Anonymous account created. Save your username and PIN!'

    if created and not anonymous_credentials:
        response_data['message'] = 'Account created successfully'

    return response_data

# Legacy endpoints for backward compatibility
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = UserRegistrationSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        
        # Add custom claims
        refresh['email'] = user.email
        refresh['is_sso_admin'] = user.is_sso_admin
        
        return Response({
            'user': UserSerializer(user).data,
            'tokens': {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    refresh_token = request.data.get('refresh')
    if not refresh_token:
        return Response({'error': 'Refresh token required'}, 
                      status=status.HTTP_400_BAD_REQUEST)
    
    try:
        refresh = RefreshToken(refresh_token)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        })
    except Exception as e:
        return Response({'error': str(e)}, 
                      status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    """
    Logout user by blacklisting refresh token and flushing session.

    HIGH-3: Properly invalidates both JWT tokens and session data.
    """
    try:
        # Blacklist the refresh token
        refresh_token = request.data.get('refresh')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()

        # HIGH-3: Flush the session to prevent session fixation
        request.session.flush()

        logger.info(f"User logged out from {request.META.get('REMOTE_ADDR')}")
        return Response({'message': 'Successfully logged out'})
    except Exception as e:
        security_logger.warning(f"Logout error: {str(e)}")
        return Response({'error': str(e)},
                      status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_access(request):
    """Verify access token"""
    return Response({
        'valid': True,
        'user': UserSerializer(request.user).data
    })

@api_view(['GET'])
@permission_classes([AllowAny])
def auth_status(request):
    """Check user authentication status"""
    if request.user.is_authenticated:
        return Response({
            'authenticated': True,
            'user': {
                'id': str(request.user.id),
                'email': request.user.email,
                'display_name': request.user.display_name,
                'auth_type': request.user.auth_type,
                'is_anonymous': request.user.is_anonymous,
                'is_sso_admin': request.user.is_sso_admin
            }
        })
    else:
        return Response({
            'authenticated': False,
            'user': None
        })

@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """Health check endpoint"""
    return Response({'status': 'healthy'})

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def applications(request):
    """Get user applications"""
    apps = Application.objects.filter(user_roles__user=request.user)
    serializer = ApplicationSerializer(apps, many=True)
    return Response(serializer.data)

@ratelimit(key='ip', rate='100/h', method='POST', block=False)
@api_view(['POST'])
@permission_classes([AllowAny])
def validate_token(request):
    """Validate and decode a JWT token"""
    from rest_framework_simplejwt.tokens import AccessToken
    from rest_framework_simplejwt.exceptions import TokenError

    # Check if rate limited
    was_limited = getattr(request, 'limited', False)
    if was_limited:
        security_logger.warning(
            f"Rate limit exceeded for token validation from {request.META.get('REMOTE_ADDR')}"
        )
        return Response(
            {'error': 'Too many requests. Please try again later.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )

    token = request.data.get('token')
    if not token:
        return Response({'valid': False, 'error': 'Token required'},
                      status=status.HTTP_400_BAD_REQUEST)
    
    try:
        access_token = AccessToken(token)
        user_id = access_token['user_id']
        user = User.objects.get(id=user_id)
        
        # Extract claims safely
        claims = {}
        for key in ['user_id', 'email', 'is_sso_admin', 'token_type', 'exp', 'iat', 'jti', 'iss']:
            if key in access_token:
                claims[key] = access_token[key]
        
        return Response({
            'valid': True,
            'user': UserSerializer(user).data,
            'claims': claims
        })
    except (TokenError, User.DoesNotExist) as e:
        return Response({'valid': False, 'error': str(e)}, 
                      status=status.HTTP_401_UNAUTHORIZED)

class ApplicationListCreateView(generics.ListCreateAPIView):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [IsAuthenticated]
    
    def perform_create(self, serializer):
        # Generate client_id and client_secret
        client_id = f"app_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)
        serializer.save(client_id=client_id, client_secret=client_secret)

class ApplicationDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Application.objects.all()
    serializer_class = ApplicationSerializer
    permission_classes = [IsAuthenticated]

class UserRoleListCreateView(generics.ListCreateAPIView):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = super().get_queryset()
        user_id = self.request.query_params.get('user_id')
        app_id = self.request.query_params.get('app_id')
        
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        if app_id:
            queryset = queryset.filter(application_id=app_id)
        
        return queryset

class UserRoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserRole.objects.all()
    serializer_class = UserRoleSerializer
    permission_classes = [IsAuthenticated]

@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def google_auth_callback(request):
    """Handle Google OAuth redirect callback.
    
    SECURITY: Uses secure two-step token exchange pattern.
    Tokens are NEVER exposed in URL - only session ID is passed.
    Frontend must exchange session_id for tokens via API call.
    """
    from django.shortcuts import redirect
    from django.contrib.auth import login as auth_login
    from django.utils import timezone
    from datetime import timedelta
    from .models import TokenExchangeSession
    
    # Get the authorization code from the callback (GET) or request data (POST)
    code = request.GET.get('code') or request.data.get('code')
    error = request.GET.get('error') or request.data.get('error')
    
    if error:
        # User cancelled or error occurred
        return redirect('/login/?error=oauth_cancelled')
    
    if not code:
        return redirect('/login/?error=no_code')
    
    try:
        # Exchange the code for tokens
        token_data = exchange_google_code_for_tokens(code)
        
        if 'error' in token_data:
            logger.error(f'Google token exchange error: {token_data}')
            return redirect('/login/?error=token_exchange_failed')
        
        # Verify ID token and get user info
        user_info = verify_google_id_token(token_data['id_token'])
        
        # Create or get user
        user, created = get_or_create_google_user(user_info)
        
        # Log the user into Django session (for @login_required views)
        auth_login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        logger.info(f'User {user.email} logged into Django session')
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        # Log success
        if created:
            logger.info(f'New Google user created: {user.email}')
        else:
            logger.info(f'Existing Google user signed in: {user.email}')
        
        # SECURITY FIX: Create secure exchange session instead of URL params
        # Tokens stored temporarily, frontend exchanges session_id for tokens
        exchange_session = TokenExchangeSession.objects.create(
            access_token=access_token,
            refresh_token=refresh_token,
            user_email=user.email,
            expires_at=timezone.now() + timedelta(seconds=60)  # 60 second expiry
        )
        
        logger.info(f'Created token exchange session {exchange_session.session_id} for {user.email}')
        
        # Redirect to dashboard instead of token exchange page
        return redirect('/dashboard/')
        
    except Exception as e:
        logger.error(f'Google OAuth callback error: {str(e)}')
        return redirect('/login/?error=oauth_failed')
