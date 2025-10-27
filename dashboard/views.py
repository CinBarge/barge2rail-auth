from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.contrib import messages
from sso.models import User, Application, UserRole


def index(request):
    if request.user.is_authenticated:
        return redirect('dashboard:dashboard')
    return redirect('dashboard:login')


def login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:dashboard')
    return render(request, 'login.html')  # Use the new clean template


def enhanced_login_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:dashboard')
    return render(request, 'dashboard/enhanced_login.html')


def google_test_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:dashboard')
    return render(request, 'dashboard/google_login.html')


def google_onetap_view(request):
    if request.user.is_authenticated:
        return redirect('dashboard:dashboard')
    return render(request, 'dashboard/google_onetap.html')


def simple_test_view(request):
    return render(request, 'dashboard/simple_test.html')


def google_diagnostic_view(request):
    from django.conf import settings
    context = {
        'google_client_id': settings.GOOGLE_CLIENT_ID,
    }
    return render(request, 'dashboard/google_diagnostic.html', context)


def google_success_view(request):
    """Handle successful Google OAuth callback"""
    access_token = request.GET.get('access_token')
    refresh_token = request.GET.get('refresh_token')
    
    context = {
        'access_token': access_token,
        'refresh_token': refresh_token,
        'success': True if access_token and refresh_token else False
    }
    return render(request, 'dashboard/google_success.html', context)


def google_oauth_callback(request):
    """Handle Google OAuth callback when code parameter is present"""
    code = request.GET.get('code')
    if code:
        # This is a Google OAuth callback
        from sso.auth_views import google_auth_callback
        return google_auth_callback(request)
    else:
        # Regular index redirect
        return index(request)


@login_required
def logout_view(request):
    logout(request)
    messages.success(request, 'Successfully logged out!')
    return redirect('dashboard:login')


@login_required
def dashboard(request):
    context = {
        'user_count': User.objects.count(),
        'app_count': Application.objects.count(),
        'role_count': UserRole.objects.count(),
        'recent_users': User.objects.order_by('-created_at')[:5],
        'recent_apps': Application.objects.order_by('-created')[:5],
    }
    return render(request, 'dashboard/dashboard.html', context)
