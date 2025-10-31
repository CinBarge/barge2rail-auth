from django.core.management.base import BaseCommand

from sso.models import User


class Command(BaseCommand):
    help = "Creates a test superuser"

    def handle(self, *args, **options):
        email = "admin@barge2rail.com"
        username = "admin"
        password = "admin123"

        if User.objects.filter(email=email).exists():
            self.stdout.write(self.style.WARNING(f"User {email} already exists"))
        else:
            user = User.objects.create_superuser(
                username=username,
                email=email,
                password=password,
                first_name="Admin",
                last_name="User",
                is_sso_admin=True,
            )
            self.stdout.write(
                self.style.SUCCESS(f"Successfully created superuser: {email}")
            )
            self.stdout.write(self.style.SUCCESS(f"Username: {username}"))
            self.stdout.write(self.style.SUCCESS(f"Password: {password}"))
