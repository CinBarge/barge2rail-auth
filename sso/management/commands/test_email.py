"""
Management command to test SendGrid email configuration.

Usage:
    python manage.py test_email recipient@example.com
"""

from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Test SendGrid email configuration"

    def add_arguments(self, parser):
        parser.add_argument("recipient", type=str, help="Email address to send test to")

    def handle(self, *args, **options):
        recipient = options["recipient"]

        self.stdout.write(self.style.NOTICE(f"Sending test email to {recipient}..."))
        self.stdout.write(self.style.NOTICE(f"Email backend: {settings.EMAIL_BACKEND}"))
        self.stdout.write(self.style.NOTICE(f"From: {settings.DEFAULT_FROM_EMAIL}"))

        try:
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
