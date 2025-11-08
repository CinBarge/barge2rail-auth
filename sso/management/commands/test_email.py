"""
Management command to test SendGrid email configuration and password reset templates.

Usage:
    # Basic test
    python manage.py test_email recipient@example.com

    # Test password reset templates
    python manage.py test_email recipient@example.com --template reset
    python manage.py test_email recipient@example.com --template confirmation
    python manage.py test_email recipient@example.com --template alert
"""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.core.management.base import BaseCommand
from django.template.loader import render_to_string
from django.utils import timezone

User = get_user_model()


class Command(BaseCommand):
    help = "Test SendGrid email configuration and password reset templates"

    def add_arguments(self, parser):
        parser.add_argument("recipient", type=str, help="Email address to send test to")
        parser.add_argument(
            "--template",
            type=str,
            choices=["reset", "confirmation", "alert"],
            help="Test specific password reset template",
        )

    def handle(self, *args, **options):
        recipient = options["recipient"]
        template = options.get("template")

        self.stdout.write(self.style.NOTICE(f"Email backend: {settings.EMAIL_BACKEND}"))
        self.stdout.write(self.style.NOTICE(f"From: {settings.DEFAULT_FROM_EMAIL}"))

        try:
            if template:
                self._send_template_test(recipient, template)
            else:
                self._send_basic_test(recipient)

            self.stdout.write(
                self.style.SUCCESS(f"✅ Test email sent successfully to {recipient}")
            )
            self.stdout.write(
                self.style.SUCCESS("Check your inbox (and spam folder if needed)")
            )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"❌ Email failed: {str(e)}"))
            self.stdout.write(
                self.style.ERROR("Check your SENDGRID_API_KEY environment variable")
            )
            raise

    def _send_basic_test(self, recipient):
        """Send basic plain text test email"""
        from django.core.mail import send_mail

        self.stdout.write(
            self.style.NOTICE(f"Sending basic test email to {recipient}...")
        )

        send_mail(
            subject="SSO Email Test",
            message=(
                "This is a test email from barge2rail SSO.\n\n"
                "If you received this email, your SendGrid "
                "configuration is working correctly!"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[recipient],
            fail_silently=False,
        )

    def _send_template_test(self, recipient, template):
        """Send HTML template test email with mock data"""
        self.stdout.write(
            self.style.NOTICE(
                f"Sending {template} template test email to {recipient}..."
            )
        )

        # Mock context data for templates
        context = self._get_template_context(template, recipient)

        # Template paths
        templates = {
            "reset": "emails/password_reset_request",
            "confirmation": "emails/password_reset_confirmation",
            "alert": "emails/password_changed_alert",
        }

        template_path = templates[template]

        # Render HTML and text versions
        html_content = render_to_string(f"{template_path}.html", context)
        text_content = render_to_string(f"{template_path}.txt", context)

        # Get subject from context
        subject = context["subject"]

        # Send multipart email
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[recipient],
        )
        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=False)

    def _get_template_context(self, template, recipient):
        """Get mock context data for template testing"""
        base_url = getattr(settings, "BASE_URL", "http://localhost:8000")

        # Mock user object
        mock_user = type(
            "MockUser",
            (),
            {
                "email": recipient,
                "first_name": "Test",
                "get_full_name": lambda: "Test User",
            },
        )

        if template == "reset":
            return {
                "subject": "Password Reset Request - Barge2Rail SSO",
                "user": mock_user,
                "reset_url": f"{base_url}/auth/reset/MOCK-TOKEN-123/",
            }
        elif template == "confirmation":
            return {
                "subject": "Password Reset Successful - Barge2Rail SSO",
                "user": mock_user,
                "login_url": f"{base_url}/auth/login/",
            }
        elif template == "alert":
            return {
                "subject": "Security Alert: Password Changed - Barge2Rail SSO",
                "user": mock_user,
                "change_date": timezone.now(),
            }
        return {}
