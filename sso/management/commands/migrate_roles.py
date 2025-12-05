"""
Management command to migrate existing ApplicationRole records to UserAppRole.

This command:
1. Reads existing ApplicationRole assignments
2. Maps legacy roles (Admin/Office/Operator/Client) to new Role model
3. Creates UserAppRole entries for the new RBAC system

The migration preserves backward compatibility - both systems can coexist.

Usage:
    # Preview what would be migrated:
    python manage.py migrate_roles --dry-run

    # Migrate all existing roles:
    python manage.py migrate_roles

    # Migrate for specific application:
    python manage.py migrate_roles --app primetrade
"""

from django.core.management.base import BaseCommand
from django.db import transaction

from sso.models import ApplicationRole, Role, UserAppRole


class Command(BaseCommand):
    help = "Migrate existing ApplicationRole records to new RBAC UserAppRole system"

    def add_arguments(self, parser):
        parser.add_argument(
            "--app",
            type=str,
            help="Specific application slug to migrate (optional)",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview migration without making changes",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        app_slug = options.get("app")

        if dry_run:
            self.stdout.write(self.style.WARNING("DRY RUN - No changes will be made"))

        # Get ApplicationRole records to migrate
        queryset = ApplicationRole.objects.select_related("user", "application")
        if app_slug:
            queryset = queryset.filter(application__slug=app_slug)

        existing_roles = list(queryset)

        if not existing_roles:
            self.stdout.write("No ApplicationRole records found to migrate.")
            return

        self.stdout.write(
            f"\nFound {len(existing_roles)} ApplicationRole record(s) to migrate"
        )

        # Track statistics
        stats = {
            "migrated": 0,
            "skipped_no_role": 0,
            "skipped_exists": 0,
            "errors": 0,
        }

        try:
            with transaction.atomic():
                for ar in existing_roles:
                    result = self._migrate_role(ar, dry_run)
                    stats[result] += 1

                if dry_run:
                    # Rollback dry run
                    transaction.set_rollback(True)

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Migration failed: {e}"))
            raise

        # Print summary
        self.stdout.write("\n=== Migration Summary ===")
        self.stdout.write(f"  Migrated: {stats['migrated']}")
        self.stdout.write(f"  Skipped (no matching role): {stats['skipped_no_role']}")
        self.stdout.write(f"  Skipped (already exists): {stats['skipped_exists']}")
        self.stdout.write(f"  Errors: {stats['errors']}")

        if dry_run:
            self.stdout.write(
                self.style.WARNING("\nDry run complete - no changes made")
            )
        else:
            self.stdout.write(self.style.SUCCESS("\nMigration complete!"))

    def _migrate_role(self, ar: ApplicationRole, dry_run: bool) -> str:
        """Migrate a single ApplicationRole to UserAppRole.

        Returns:
            str: Result status ('migrated', 'skipped_no_role', 'skipped_exists', 'errors')
        """
        user_id = ar.user.email or ar.user.anonymous_username or str(ar.user.id)
        app_name = ar.application.name
        legacy_role = ar.role

        # Find matching Role in new RBAC system
        # Roles have legacy_role field that maps to old role names
        # Use case-insensitive matching since legacy data may vary
        try:
            new_role = Role.objects.get(
                application=ar.application,
                legacy_role__iexact=legacy_role,
                is_active=True,
            )
        except Role.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(
                    f"  [SKIP] {user_id} → {app_name}: "
                    f"No Role found with legacy_role='{legacy_role}'"
                )
            )
            return "skipped_no_role"
        except Role.MultipleObjectsReturned:
            # Multiple roles match - use first one
            new_role = Role.objects.filter(
                application=ar.application,
                legacy_role__iexact=legacy_role,
                is_active=True,
            ).first()

        # Check if UserAppRole already exists
        if UserAppRole.objects.filter(
            user=ar.user,
            role=new_role,
        ).exists():
            self.stdout.write(
                f"  [EXISTS] {user_id} → {app_name}: " f"Already has {new_role.name}"
            )
            return "skipped_exists"

        # Create new UserAppRole
        if not dry_run:
            UserAppRole.objects.create(
                user=ar.user,
                role=new_role,
                notes=f"Migrated from ApplicationRole (legacy role: {legacy_role})",
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"  [MIGRATE] {user_id} → {app_name}: "
                f"{legacy_role} → {new_role.name}"
            )
        )
        return "migrated"
