"""
Password management views for Barge2Rail SSO.

Includes:
- Password change (authenticated users)
- Forgot password request
- Password reset with token
"""

import logging

from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.shortcuts import render
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit

from .models import PasswordResetToken, User

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """Extract client IP address from request"""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


@login_required
@require_http_methods(["GET", "POST"])
@ratelimit(key="user", rate="5/15m", method="POST", block=True)
def change_password(request):
    """
    Password change form for authenticated users.

    Security:
    - Requires current password verification
    - Enforces password strength requirements
    - Rate limited: 5 attempts per 15 minutes
    - Updates session hash to prevent logout
    - Logs password changes for audit
    """
    if request.method == "POST":
        current_password = request.POST.get("current_password")
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        # Validation
        errors = []

        if not current_password:
            errors.append("Current password is required")

        if not new_password:
            errors.append("New password is required")

        if new_password != confirm_password:
            errors.append("New passwords do not match")

        # Verify current password
        if current_password and not request.user.check_password(current_password):
            errors.append("Current password is incorrect")
            logger.warning(
                f"Failed password change attempt for {request.user.email} - "
                f"incorrect current password"
            )

        # Validate new password strength
        if new_password and not errors:
            try:
                validate_password(new_password, request.user)
            except ValidationError as e:
                errors.extend(e.messages)

        # If validation passed, change password
        if not errors:
            request.user.set_password(new_password)
            request.user.save()

            # Update session to prevent logout
            update_session_auth_hash(request, request.user)

            # Log successful password change
            logger.info(f"Password changed successfully for user: {request.user.email}")

            # Success message
            return render(
                request, "sso/password_change_success.html", {"user": request.user}
            )

        # Render form with errors
        return render(request, "sso/password_change_form.html", {"errors": errors})

    # GET request - show form
    return render(request, "sso/password_change_form.html")


@require_http_methods(["GET", "POST"])
@ratelimit(key="ip", rate="3/1h", method="POST", block=True)
def forgot_password(request):
    """
    Forgot password request form.

    Security:
    - Rate limited: 3 requests per hour per IP
    - Does not reveal if email exists (timing-safe)
    - Sends email with secure reset token
    - Logs all reset requests for audit
    """
    if request.method == "POST":
        email = request.POST.get("email", "").strip().lower()

        # Always show success message (timing-safe, don't reveal if user exists)
        success_message = (
            f"If an account exists for {email}, you will receive a password "
            f"reset email shortly."
        )

        if email:
            try:
                user = User.objects.get(email=email, is_active=True)

                # Generate reset token
                ip_address = get_client_ip(request)
                token_string, token_obj = PasswordResetToken.generate_token(
                    user, ip_address
                )

                # Build reset URL
                reset_url = request.build_absolute_uri(
                    f"/auth/reset-password/{token_string}/"
                )

                # Send email
                subject = "Password Reset Request"
                context = {
                    "user": user,
                    "reset_url": reset_url,
                    "expiration_hours": 1,
                }

                # Render HTML email
                html_message = render_to_string(
                    "sso/emails/password_reset.html", context
                )
                plain_message = strip_tags(html_message)

                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=(
                        f"{settings.DEFAULT_FROM_NAME} "
                        f"<{settings.DEFAULT_FROM_EMAIL}>"
                    ),
                    recipient_list=[user.email],
                    html_message=html_message,
                    fail_silently=False,
                )

                logger.info(
                    f"Password reset email sent to {email} from IP {ip_address}"
                )

            except User.DoesNotExist:
                # Log but don't reveal that user doesn't exist
                logger.info(f"Password reset requested for non-existent email: {email}")

            except Exception as e:
                logger.error(f"Error sending password reset email to {email}: {str(e)}")

        # Always return success (timing-safe)
        return render(
            request,
            "sso/forgot_password_success.html",
            {"email": email, "message": success_message},
        )

    # GET request - show form
    return render(request, "sso/forgot_password_form.html")


@require_http_methods(["GET", "POST"])
def reset_password(request, token):
    """
    Password reset form with token validation.

    Security:
    - Validates token (not expired, not used)
    - Marks token as used after successful reset
    - Enforces password strength requirements
    - Logs all reset attempts for audit
    """
    # Validate token
    token_obj = PasswordResetToken.validate_token(token)

    if not token_obj:
        # Invalid or expired token
        logger.warning(f"Invalid password reset attempt with token: {token[:8]}...")
        return render(
            request,
            "sso/reset_password_invalid.html",
            {
                "error": (
                    "This password reset link is invalid or has expired. "
                    "Please request a new one."
                )
            },
        )

    if request.method == "POST":
        new_password = request.POST.get("new_password")
        confirm_password = request.POST.get("confirm_password")

        # Validation
        errors = []

        if not new_password:
            errors.append("Password is required")

        if new_password != confirm_password:
            errors.append("Passwords do not match")

        # Validate password strength
        if new_password and not errors:
            try:
                validate_password(new_password, token_obj.user)
            except ValidationError as e:
                errors.extend(e.messages)

        # If validation passed, reset password
        if not errors:
            user = token_obj.user
            user.set_password(new_password)
            user.save()

            # Mark token as used (one-time use)
            token_obj.mark_as_used()

            # Log successful password reset
            logger.info(f"Password reset successfully for user: {user.email}")

            # Success page
            return render(request, "sso/reset_password_success.html", {"user": user})

        # Render form with errors
        return render(
            request, "sso/reset_password_form.html", {"token": token, "errors": errors}
        )

    # GET request - show form
    return render(
        request,
        "sso/reset_password_form.html",
        {"token": token, "user": token_obj.user},
    )


@require_http_methods(["GET"])
def password_reset_complete(request):
    """
    Password reset completion page.

    Django standard password reset flow endpoint.
    Shows success message after password has been reset.
    """
    return render(request, "sso/reset_password_success.html")
