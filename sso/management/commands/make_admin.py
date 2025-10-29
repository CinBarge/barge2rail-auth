from django.core.management.base import BaseCommand

from sso.models import User


class Command(BaseCommand):
    help = "Grant admin permissions to a user by email"

    def add_arguments(self, parser):
        parser.add_argument("email", type=str, help="Email address of the user")

    def handle(self, *args, **options):
        email = options["email"]

        try:
            user = User.objects.get(email=email)
            user.is_staff = True
            user.is_superuser = True
            user.is_sso_admin = True
            user.save()

            self.stdout.write(
                self.style.SUCCESS(
                    f"✓ Successfully granted admin permissions to {email}"
                )
            )
            self.stdout.write(f"  - is_staff: {user.is_staff}")
            self.stdout.write(f"  - is_superuser: {user.is_superuser}")
            self.stdout.write(f"  - is_sso_admin: {user.is_sso_admin}")

        except User.DoesNotExist:
            self.stdout.write(
                self.style.ERROR(f"✗ User with email {email} does not exist")
            )
