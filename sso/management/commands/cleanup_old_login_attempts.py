"""
Management command to clean up old login attempt records.

Usage:
    python manage.py cleanup_old_login_attempts

This should be run periodically (e.g., daily via cron) to remove login attempts
older than 24 hours to prevent database bloat while maintaining security logs.

Recommended schedule: Daily at midnight
"""

from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from sso.models import LoginAttempt


class Command(BaseCommand):
    help = 'Clean up login attempt records older than 24 hours'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Show detailed output',
        )
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Delete attempts older than this many hours (default: 24)',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        verbose = options['verbose']
        hours = options['hours']

        cutoff_time = timezone.now() - timedelta(hours=hours)

        # Find old login attempts
        old_attempts = LoginAttempt.objects.filter(
            attempted_at__lt=cutoff_time
        )
        count = old_attempts.count()

        if verbose:
            self.stdout.write(f"Found {count} login attempts older than {hours} hours")
            self.stdout.write(f"Cutoff time: {cutoff_time}")

        if count == 0:
            self.stdout.write(self.style.SUCCESS('No old login attempts to clean up'))
            return

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f'DRY RUN: Would delete {count} login attempts'
                )
            )
            if verbose:
                self.stdout.write("Sample attempts to be deleted:")
                for attempt in old_attempts[:10]:  # Show first 10
                    status = "successful" if attempt.success else "failed"
                    self.stdout.write(
                        f"  - {status} login for {attempt.identifier} from "
                        f"{attempt.ip_address} at {attempt.attempted_at}"
                    )
                if count > 10:
                    self.stdout.write(f"  ... and {count - 10} more")
        else:
            # Actually delete
            deleted_count, _ = old_attempts.delete()

            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully deleted {deleted_count} old login attempts'
                )
            )
