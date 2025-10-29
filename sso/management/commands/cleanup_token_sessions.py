"""
Management command to clean up expired token exchange sessions.

Usage:
    python manage.py cleanup_token_sessions

This should be run periodically (e.g., via cron or scheduled task) to remove:
- Expired sessions (older than expiry time)
- Used sessions (older than 1 hour)

Recommended schedule: Every hour
"""

from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from sso.models import TokenExchangeSession


class Command(BaseCommand):
    help = "Clean up expired and used token exchange sessions"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be deleted without actually deleting",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Show detailed output",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        verbose = options["verbose"]

        now = timezone.now()

        # Find expired sessions
        expired_sessions = TokenExchangeSession.objects.filter(expires_at__lt=now)
        expired_count = expired_sessions.count()

        # Find old used sessions (over 1 hour old)
        old_used_sessions = TokenExchangeSession.objects.filter(
            used=True, created_at__lt=now - timedelta(hours=1)
        )
        old_used_count = old_used_sessions.count()

        total_to_delete = expired_count + old_used_count

        if verbose:
            self.stdout.write(f"Found {expired_count} expired sessions")
            self.stdout.write(f"Found {old_used_count} old used sessions")
            self.stdout.write(f"Total to delete: {total_to_delete}")

        if total_to_delete == 0:
            self.stdout.write(self.style.SUCCESS("No sessions to clean up"))
            return

        if dry_run:
            self.stdout.write(
                self.style.WARNING(f"DRY RUN: Would delete {total_to_delete} sessions")
            )
            if verbose:
                self.stdout.write("Expired sessions:")
                for session in expired_sessions[:10]:  # Show first 10
                    self.stdout.write(
                        f"  - {session.session_id} for {session.user_email} "
                        f"(expired {session.expires_at})"
                    )
                if expired_count > 10:
                    self.stdout.write(f"  ... and {expired_count - 10} more")
        else:
            # Actually delete
            deleted_expired, _ = expired_sessions.delete()
            deleted_used, _ = old_used_sessions.delete()
            total_deleted = deleted_expired + deleted_used

            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully deleted {total_deleted} token exchange sessions"
                )
            )
            if verbose:
                self.stdout.write(f"  - {deleted_expired} expired sessions")
                self.stdout.write(f"  - {deleted_used} old used sessions")
