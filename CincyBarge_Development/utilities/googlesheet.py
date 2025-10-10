# utilities/googlesheet.py

import os
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Define your scopes
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

# Path to your service account JSON key file
SERVICE_ACCOUNT_FILE = "C:\\Users\\zx360\\Downloads\\URC Sacks - BOL Data.csv"

# Default spreadsheet and sheet info - change as needed
DEFAULT_SPREADSHEET_ID = "1fAVM-YAh8I7DE2WjcHS5l8N7h_C_i4bNnLk7EKXwRjo"
DEFAULT_SHEET_NAME = "CoilScans"
DEFAULT_RANGE = "A1:D100"

def get_credentials():
    """Get credentials from service account file."""
    creds = Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE,
        scopes=SCOPES
    )
    return creds

def get_sheet_data(sheet_id=None, range_name=None):
    """Fetch data from Google Sheets and return as list of dicts."""
    try:
        if sheet_id is None:
            sheet_id = DEFAULT_SPREADSHEET_ID
        if range_name is None:
            range_name = f"{DEFAULT_SHEET_NAME}!{DEFAULT_RANGE}"

        creds = get_credentials()
        service = build('sheets', 'v4', credentials=creds)
        sheet = service.spreadsheets()

        result = sheet.values().get(
            spreadsheetId=sheet_id,
            range=range_name
        ).execute()

        values = result.get('values', [])

        if not values:
            return []

        headers = values[0]
        data = []

        for row in values[1:]:
            while len(row) < len(headers):
                row.append('')
            row_dict = {headers[i]: row[i] for i in range(len(headers))}
            row_dict['row_index'] = values.index(row) + 2  # accounting header & 1-indexed rows
            data.append(row_dict)

        return data

    except HttpError as err:
        print(f"Google Sheets API Error: {err}")
        return []
    except Exception as e:
        print(f"Error fetching sheet data: {e}")
        return []

def update_sheet_cell(row_index, column, value, sheet_id=None, sheet_name=None):
    """Update a specific cell in Google Sheets."""
    try:
        if sheet_id is None:
            sheet_id = DEFAULT_SPREADSHEET_ID
        if sheet_name is None:
            sheet_name = DEFAULT_SHEET_NAME

        creds = get_credentials()
        service = build('sheets', 'v4', credentials=creds)

        range_name = f"{sheet_name}!{column}{row_index}"

        body = {
            'values': [[value]]
        }

        result = service.spreadsheets().values().update(
            spreadsheetId=sheet_id,
            range=range_name,
            valueInputOption='USER_ENTERED',
            body=body
        ).execute()

        return {'success': True, 'updated_cells': result.get('updatedCells')}

    except HttpError as err:
        print(f"Google Sheets API Error: {err}")
        return {'success': False, 'error': str(err)}
    except Exception as e:
        print(f"Error updating sheet: {e}")
        return {'success': False, 'error': str(e)}

def update_sheet_row(row_index, row_data, sheet_id=None, sheet_name=None):
    """Update an entire row in Google Sheets."""
    try:
        if sheet_id is None:
            sheet_id = DEFAULT_SPREADSHEET_ID
        if sheet_name is None:
            sheet_name = DEFAULT_SHEET_NAME

        creds = get_credentials()
        service = build('sheets', 'v4', credentials=creds)

        header_result = service.spreadsheets().values().get(
            spreadsheetId=sheet_id,
            range=f"{sheet_name}!1:1"
        ).execute()

        headers = header_result.get('values', [[]])[0]

        row_values = [row_data.get(header, '') for header in headers]

        # Calculate column letter for range end
        end_column_letter = chr(65 + len(headers) - 1)
        range_name = f"{sheet_name}!A{row_index}:{end_column_letter}{row_index}"

        body = {
            'values': [row_values]
        }

        result = service.spreadsheets().values().update(
            spreadsheetId=sheet_id,
            range=range_name,
            valueInputOption='USER_ENTERED',
            body=body
        ).execute()

        return {'success': True, 'updated_cells': result.get('updatedCells')}

    except HttpError as err:
        print(f"Google Sheets API Error: {err}")
        return {'success': False, 'error': str(err)}
    except Exception as e:
        print(f"Error updating sheet row: {e}")
        return {'success': False, 'error': str(e)}

def append_sheet_row(row_data, sheet_id=None, sheet_name=None):
    """Append a new row to Google Sheets."""
    try:
        if sheet_id is None:
            sheet_id = DEFAULT_SPREADSHEET_ID
        if sheet_name is None:
            sheet_name = DEFAULT_SHEET_NAME

        creds = get_credentials()
        service = build('sheets', 'v4', credentials=creds)

        header_result = service.spreadsheets().values().get(
            spreadsheetId=sheet_id,
            range=f"{sheet_name}!1:1"
        ).execute()

        headers = header_result.get('values', [[]])[0]

        row_values = [row_data.get(header, '') for header in headers]

        body = {
            'values': [row_values]
        }

        result = service.spreadsheets().values().append(
            spreadsheetId=sheet_id,
            range=f"{sheet_name}!A:A",
            valueInputOption='USER_ENTERED',
            insertDataOption='INSERT_ROWS',
            body=body
        ).execute()

        return {'success': True, 'updates': result.get('updates')}

    except HttpError as err:
        print(f"Google Sheets API Error: {err}")
        return {'success': False, 'error': str(err)}
    except Exception as e:
        print(f"Error appending sheet row: {e}")
        return {'success': False, 'error': str(e)}

def sync_sheet_to_database(sheet_id=None, sheet_name=None, range_name=None):
    """Sync Google Sheets data to Django database."""
    try:
        if sheet_id is None:
            sheet_id = DEFAULT_SPREADSHEET_ID
        if sheet_name is None:
            sheet_name = DEFAULT_SHEET_NAME
        if range_name is None:
            range_name = f"{sheet_name}!{DEFAULT_RANGE}"

        from dashboard.models import Product, CATEGORY  # Import models here to avoid circular imports

        data = get_sheet_data(sheet_id=sheet_id, range_name=range_name)

        if not data:
            return {
                'success': False,
                'error': 'No data found in Google Sheets',
                'synced': 0,
                'errors': []
            }

        synced_count = 0
        errors = []
        valid_categories = dict(CATEGORY)

        for row in data:
            try:
                name = row.get('Name', row.get('name', '')).strip()
                category = row.get('Category', row.get('category', '')).strip()
                quantity_str = row.get('Quantity', row.get('quantity', '0')).strip()

                if not name:
                    continue

                try:
                    quantity = int(quantity_str) if quantity_str else 0
                except (ValueError, TypeError):
                    quantity = 0

                if category not in valid_categories:
                    # Case-insensitive matching
                    category_match = None
                    for valid_cat in valid_categories.keys():
                        if valid_cat.lower() == category.lower():
                            category_match = valid_cat
                            break

                    if category_match:
                        category = category_match
                    else:
                        errors.append(f"Invalid category '{category}' for product '{name}'")
                        continue

                product, created = Product.objects.update_or_create(
                    name=name,
                    defaults={
                        'category': category,
                        'quantity': quantity
                    }
                )
                synced_count += 1

            except Exception as e:
                errors.append(f"Error syncing row: {str(e)}")
                continue

        return {
            'success': True,
            'synced': synced_count,
            'errors': errors,
            'total_rows': len(data)
        }

    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'synced': 0,
            'errors': []
        }
