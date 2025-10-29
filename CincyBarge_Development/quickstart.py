import hashlib
import os.path
import sys
import time

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

# The ID and range of a sample spreadsheet.
SAMPLE_SPREADSHEET_ID = "1fAVM-YAh8I7DE2WjcHS5l8N7h_C_i4bNnLk7EKXwRjo"
SAMPLE_RANGE_NAME = "CoilScans!A1:D5"


# ========== New: Hash Function ==========
def hash_values(values):
    """Generate a simple hash from spreadsheet data to detect changes."""
    flat_data = str(values).encode("utf-8")
    return hashlib.md5(flat_data).hexdigest()


# ========== Optional: Force Reauth ==========
def refresh_token():
    """Force refresh the authentication token."""
    if os.path.exists("token.json"):
        print("Deleting existing token...")
        os.remove("token.json")
    print("Token deleted. Next run will require re-authentication.")


# ========== Main App ==========
def main():
    """Connects to Google Sheets and monitors a range for changes."""
    creds = None

    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(
                port=8000, access_type="offline", prompt="consent"
            )

        with open("token.json", "w") as token:
            token.write(creds.to_json())

    try:

        service = build("sheets", "v4", credentials=creds)
        sheet = service.spreadsheets()

        print("✅ Connected to Google Sheets.")
        print(f"Monitoring range: {SAMPLE_RANGE_NAME}")
        print("Polling every 30 seconds...\n")

        previous_hash = None

        while True:
            # Read current values from sheet
            result = (
                sheet.values()
                .get(spreadsheetId=SAMPLE_SPREADSHEET_ID, range=SAMPLE_RANGE_NAME)
                .execute()
            )
            values = result.get("values", [])
            current_hash = hash_values(values)

            if current_hash != previous_hash:
                print(f"\n🔄 Change detected at {time.strftime('%Y-%m-%d %H:%M:%S')}")
                print("-" * 50)
                if values:
                    for i, row in enumerate(values, 1):
                        print(f"Row {i}: {row}")
                    print(f"Total rows: {len(values)}")
                else:
                    print("⚠️ No data found in the range.")
                print("-" * 50)
                previous_hash = current_hash
            else:
                print(f"No change detected at {time.strftime('%H:%M:%S')}")

            time.sleep(30)  # Wait 30 seconds before next check

    except HttpError as err:
        print("❌ API Error:", err)


# ========== Entry Point ==========
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--refresh-token":
        refresh_token()
        print("Token refreshed. Initiating reauth.")
        main()
    else:
        main()
