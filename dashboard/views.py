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
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                login(request, user)
                messages.success(request, 'Successfully logged in!')
                return redirect('dashboard:dashboard')
            else:
                messages.error(request, 'Invalid credentials')
        except User.DoesNotExist:
            messages.error(request, 'Invalid credentials')
    
    return render(request, 'dashboard/login.html')


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
        'recent_apps': Application.objects.order_by('-created_at')[:5],
    }
    return render(request, 'dashboard/dashboard.html', context)
