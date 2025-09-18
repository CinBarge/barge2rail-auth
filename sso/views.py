import requests
import logging
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, generics
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import User, Application, UserRole
from .serializers import (
    UserSerializer, UserRegistrationSerializer, LoginSerializer,
    ApplicationSerializer, UserRoleSerializer
)
import secrets

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_google_oauth(request):
    """Handle Google OAuth code exchange"""
    code = request.data.get('code')
    
    if not code:
        return Response({'error': 'No authorization code provided'}, status=400)
    
    try:
        # Exchange code for tokens
        token_data = exchange_google_code_for_tokens(code)
        
        if 'error' in token_data:
            logger.error(f'Google token exchange error: {token_data}')
            return Response({'error': token_data.get('error_description', 'Token exchange failed')}, status=400)
        
        # Verify ID token and get user info
        user_info = verify_google_id_token(token_data['id_token'])
        
        # Create or get user
        user, created = get_or_create_google_user(user_info)
        
        # Generate JWT tokens
        response_data = generate_token_response(user, created=created)
        
        if created:
            logger.info(f'New Google user created: {user.email}')
        else:
            logger.info(f'Existing Google user signed in: {user.email}')
            
        return Response(response_data)
        
    except Exception as e:
        logger.error(f'Google OAuth error: {str(e)}')
        return Response({'error': 'Google authentication failed'}, status=400)

def exchange_google_code_for_tokens(code):
    """Exchange authorization code for access/ID tokens"""
    token_url = 'https://oauth2.googleapis.com/token'
    
    redirect_uri = f'{settings.BASE_URL}/auth/google/callback'
    
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

def get_or_create_google_user(user_info):
    """Get or create user from Google info"""
    try:
        # Try to find existing user by Google ID
        user = User.objects.get(google_id=user_info['google_id'])
        
        # Update user info
        user.email = user_info['email']
        user.display_name = user_info['name']
        if not user.is_active:
            user.is_active = True
        user.save()
        
        logger.info(f'Updated existing Google user: {user.email}')
        return user, False
        
    except User.DoesNotExist:
        # Check if email already exists with different auth method
        existing_user = User.objects.filter(email=user_info['email']).first()
        if existing_user:
            # Link Google account to existing user
            existing_user.google_id = user_info['google_id']
            existing_user.auth_type = 'google'
            existing_user.save()
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

@api_view(['POST'])
@permission_classes([AllowAny])
def login_email(request):
    """Traditional email/password login"""
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not email or not password:
        return Response({'error': 'Email and password required'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    user = authenticate(username=email, password=password)
    if not user:
        return Response({'error': 'Invalid credentials'}, 
                       status=status.HTTP_401_UNAUTHORIZED)
    
    return generate_token_response(user)

@api_view(['POST'])
@permission_classes([AllowAny])
def login_anonymous(request):
    """Anonymous login with username and PIN"""
    username = request.data.get('username')
    pin = request.data.get('pin')
    
    if username and pin:
        # Existing anonymous user login
        try:
            user = User.objects.get(
                anonymous_username=username,
                pin_code=pin,
                is_anonymous=True
            )
            return generate_token_response(user)
        except User.DoesNotExist:
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
        
        return generate_token_response(user, anonymous_credentials={
            'username': user.anonymous_username,
            'pin': user.pin_code
        })

@api_view(['POST'])
@permission_classes([AllowAny])
def register_email(request):
    """Register new email/password user"""
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
    
    return generate_token_response(user, created=True)

@api_view(['GET'])
@permission_classes([AllowAny])
def google_oauth_url(request):
    """Generate Google OAuth URL for manual testing"""
    redirect_uri = f'{settings.BASE_URL}/auth/google/callback'
    
    params = {
        'client_id': settings.GOOGLE_CLIENT_ID,
        'redirect_uri': redirect_uri,
        'scope': 'openid email profile',
        'response_type': 'code',
        'access_type': 'offline',
        'prompt': 'select_account'
    }
    
    from urllib.parse import urlencode
    auth_url = f'https://accounts.google.com/oauth/authorize?{urlencode(params)}'
    
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
        'redirect_uri': f'{settings.BASE_URL}/auth/google/callback'
    }
    
    # Check if all required settings are present
    all_configured = all([
        settings.GOOGLE_CLIENT_ID,
        settings.GOOGLE_CLIENT_SECRET,
        settings.BASE_URL
    ])
    
    config_status['fully_configured'] = all_configured
    
    return Response(config_status)

def generate_token_response(user, created=False, anonymous_credentials=None):
    """Generate JWT token response"""
    refresh = RefreshToken.for_user(user)
    
    # Add custom claims
    refresh['email'] = user.email if user.email else ''
    refresh['is_sso_admin'] = user.is_sso_admin
    refresh['auth_type'] = user.auth_type
    refresh['is_anonymous'] = user.is_anonymous
    refresh['display_name'] = user.display_name
    
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
        response_data['anonymous_credentials'] = anonymous_credentials
        response_data['message'] = 'Anonymous account created. Save your username and PIN!'
    
    if created and not anonymous_credentials:
        response_data['message'] = 'Account created successfully'
    
    return Response(response_data)

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
    try:
        refresh_token = request.data.get('refresh')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        return Response({'message': 'Successfully logged out'})
    except Exception as e:
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

@api_view(['POST'])
@permission_classes([AllowAny])
def validate_token(request):
    """Validate and decode a JWT token"""
    from rest_framework_simplejwt.tokens import AccessToken
    from rest_framework_simplejwt.exceptions import TokenError
    
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
    """Handle Google OAuth redirect callback"""
    from django.shortcuts import redirect
    
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
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        
        # Log success
        if created:
            logger.info(f'New Google user created: {user.email}')
        else:
            logger.info(f'Existing Google user signed in: {user.email}')
        
        # Redirect to success page with tokens as URL parameters
        # In production, you'd want to use a more secure method
        return redirect(f'/login/google-success/?access_token={access_token}&refresh_token={refresh_token}&email={user.email}')
        
    except Exception as e:
        logger.error(f'Google OAuth callback error: {str(e)}')
        return redirect('/login/?error=oauth_failed')
