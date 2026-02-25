import logging

from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from sso.models import Application, User, UserRole

security_logger = logging.getLogger("django.security")


def index(request):
    if request.user.is_authenticated:
        return redirect("dashboard:dashboard")
    return redirect("sso:login")


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:dashboard")
    return render(request, "login.html")  # Use the new clean template


def enhanced_login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:dashboard")
    return render(request, "dashboard/enhanced_login.html")


def google_test_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:dashboard")
    return render(request, "dashboard/google_login.html")


def google_onetap_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard:dashboard")
    return render(request, "dashboard/google_onetap.html")


def simple_test_view(request):
    return render(request, "dashboard/simple_test.html")


def google_success_view(request):
    """Handle successful Google OAuth callback"""
    access_token = request.GET.get("access_token")
    refresh_token = request.GET.get("refresh_token")

    context = {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "success": True if access_token and refresh_token else False,
    }
    return render(request, "dashboard/google_success.html", context)


def google_oauth_callback(request):
    """Handle Google OAuth callback when code parameter is present"""
    code = request.GET.get("code")
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
    messages.success(request, "Successfully logged out!")
    return redirect("sso:login")


@login_required
def dashboard(request):
    # SECURITY: Dashboard exposes cross-tenant PII (user emails, app client IDs).
    # Only SSO admins and staff may view it.
    if not (request.user.is_sso_admin or request.user.is_staff):
        security_logger.warning(
            "Unauthorized SSO dashboard access attempt: "
            "user=%s, path=%s, ip=%s, is_staff=%s, is_sso_admin=%s",
            request.user.email,
            request.path,
            request.META.get("REMOTE_ADDR"),
            request.user.is_staff,
            request.user.is_sso_admin,
        )
        return render(request, "dashboard/access_denied.html", status=403)

    context = {
        "user_count": User.objects.count(),
        "app_count": Application.objects.count(),
        "role_count": UserRole.objects.count(),
        "recent_users": User.objects.order_by("-created_at")[:5],
        "recent_apps": Application.objects.order_by("-created")[:5],
    }
    return render(request, "dashboard/dashboard.html", context)
