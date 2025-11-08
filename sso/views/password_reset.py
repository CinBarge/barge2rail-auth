from django.conf import settings
from django.contrib.auth.views import (
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils import timezone

from ..forms.password_reset import PasswordResetConfirmForm, PasswordResetRequestForm


class CustomPasswordResetView(PasswordResetView):
    """
    Password reset request view.
    """

    form_class = PasswordResetRequestForm
    template_name = "password_reset/request.html"
    success_url = reverse_lazy("password_reset_sent")
    email_template_name = "emails/password_reset_request.txt"
    html_email_template_name = "emails/password_reset_request.html"


class CustomPasswordResetDoneView(PasswordResetDoneView):
    """
    Confirmation that password reset email was sent.
    """

    template_name = "password_reset/sent.html"


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """
    Password reset confirmation view (user enters new password).
    """

    form_class = PasswordResetConfirmForm
    template_name = "password_reset/confirm.html"
    success_url = reverse_lazy("password_reset_done")

    def form_valid(self, form):
        """
        After password is changed, send confirmation email.
        """
        response = super().form_valid(form)

        # Send password changed alert email
        user = form.user
        context = {
            "user": user,
            "change_date": timezone.now(),
        }

        text_message = render_to_string("emails/password_changed_alert.txt", context)
        html_message = render_to_string("emails/password_changed_alert.html", context)

        email = EmailMultiAlternatives(
            subject="Security Alert: Password Changed - Barge2Rail SSO",
            body=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email],
        )
        email.attach_alternative(html_message, "text/html")
        email.send()

        return response


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    """
    Success page after password reset.
    """

    template_name = "password_reset/done.html"
