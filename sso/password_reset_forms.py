from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

User = get_user_model()


class PasswordResetRequestForm(PasswordResetForm):
    """
    Custom password reset form that uses our email templates.
    """

    email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter your email address",
                "autocomplete": "email",
            }
        ),
    )

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        """
        Send password reset email using our custom templates.
        """
        # Build reset URL
        uid = urlsafe_base64_encode(force_bytes(context["user"].pk))
        token = context["token"]
        reset_url = f"{settings.BASE_URL}/password/reset/{uid}/{token}/"

        # Prepare context for templates
        email_context = {
            "user": context["user"],
            "reset_url": reset_url,
        }

        # Render templates
        text_message = render_to_string(
            "emails/password_reset_request.txt", email_context
        )
        html_message = render_to_string(
            "emails/password_reset_request.html", email_context
        )

        # Send email
        email = EmailMultiAlternatives(
            subject="Reset Your Password - Barge2Rail SSO",
            body=text_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[to_email],
        )
        email.attach_alternative(html_message, "text/html")
        email.send()


class PasswordResetConfirmForm(SetPasswordForm):
    """
    Custom set password form with better styling.
    """

    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Enter new password",
                "autocomplete": "new-password",
            }
        ),
        strip=False,
    )
    new_password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "Confirm new password",
                "autocomplete": "new-password",
            }
        ),
        strip=False,
    )
