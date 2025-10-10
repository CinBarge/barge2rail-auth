from django.core.management.base import BaseCommand
from yourapp.utils.sheet_sync import sync_google_sheet_to_db

class Command(BaseCommand):
    help = 'Sync products from Google Sheets into SQLite DB'

    def handle(self, *args, **kwargs):
        SHEET_ID = '17ZsO4oRTg5aN59tWSrZYn5pc1C8NzgUP2whdUkmpGGY'
        sync_google_sheet_to_db(SHEET_ID)
        self.stdout.write(self.style.SUCCESS("✅ Products synced successfully from Google Sheets."))
