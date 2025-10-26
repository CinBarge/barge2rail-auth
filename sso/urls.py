from django.urls import path
from django.shortcuts import redirect
from django.urls import reverse
from urllib.parse import urlencode
from . import views, auth_views, oauth_views

# Admin OAuth redirects - these bridge to the main OAuth flow
def admin_google_login_redirect(request):
    """Redirect admin login to main OAuth, preserving next parameter"""
    next_url = request.GET.get('next', '/admin/')
    oauth_url = reverse('login_google')
    return redirect(f"{oauth_url}?{urlencode({'next': next_url})}")

def admin_google_callback_redirect(request):
    """This shouldn't be hit, but redirect to main callback if it is"""
    return redirect(reverse('google_auth_callback') + '?' + request.GET.urlencode())

urlpatterns = [
    # Admin Google OAuth - NOW JUST REDIRECTS TO MAIN OAUTH
    path('admin/google/login/', admin_google_login_redirect, name='admin_google_login'),
    path('admin/google/callback/', admin_google_callback_redirect, name='admin_google_callback'),

    # MAIN Google OAuth - THE ONLY REAL IMPLEMENTATION
    path('login/google/', auth_views.login_google, name='login_google'),
    path('google/callback/', auth_views.google_auth_callback, name='google_auth_callback'),

    # Email Authentication
    path('login/email/', auth_views.login_email, name='login_email'),
    path('register/email/', auth_views.register_email, name='register_email'),

    # Anonymous Authentication
    path('login/anonymous/', auth_views.login_anonymous, name='login_anonymous'),

    # Token Management
    path('refresh/', views.refresh_token, name='refresh_token'),
    path('validate/', views.validate_token, name='validate_token'),

    # User Profile
    path('me/', views.user_profile, name='user_profile'),
    path('verify/', views.verify_access, name='verify_access'),
    path('health/', views.health_check, name='health_check'),
    path('config/google/', views.google_config_check, name='google_config_check'),

    # Core Authentication
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),

    # Debug
    path('debug/google/', auth_views.debug_google_config, name='debug_google_config'),
]