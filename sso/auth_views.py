from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
try:
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False
from decouple import config
from .models import User, UserRole
from .serializers import UserSerializer


# Google OAuth settings
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID', default='')


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
def login_google(request):
    """Google Sign-In authentication"""
    token = request.data.get('token')
    
    if not token:
        return Response({'error': 'Google token required'}, 
                       status=status.HTTP_400_BAD_REQUEST)
    
    if not GOOGLE_AUTH_AVAILABLE:
        return Response({'error': 'Google authentication not available'}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    if not GOOGLE_CLIENT_ID:
        return Response({'error': 'Google OAuth not configured'}, 
                       status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    try:
        # Verify Google token
        idinfo = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        
        google_id = idinfo['sub']
        email = idinfo['email']
        name = idinfo.get('name', '')
        
        # Find or create user
        user, created = User.objects.get_or_create(
            google_id=google_id,
            defaults={
                'email': email,
                'username': email,  # Use email as username for Google users
                'display_name': name,
                'first_name': idinfo.get('given_name', ''),
                'last_name': idinfo.get('family_name', ''),
                'auth_type': 'google',
                'is_active': True,
            }
        )
        
        # Update user info if existing
        if not created:
            user.email = email
            user.display_name = name
            user.first_name = idinfo.get('given_name', '')
            user.last_name = idinfo.get('family_name', '')
            user.save()
        
        return generate_token_response(user, created=created)
        
    except ValueError as e:
        return Response({'error': 'Invalid Google token'}, 
                       status=status.HTTP_400_BAD_REQUEST)


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