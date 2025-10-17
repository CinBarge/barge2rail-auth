# Bill of Lading Template Feature

## Overview
This feature allows users to upload and manage Bill of Lading (BOL) templates for each supplier. The templates support both document formats (PDF, DOCX, HTML) and spreadsheet formats (CSV, Excel) with field mapping capabilities. Templates can be used as reference points when generating bills of lading.

## Features Implemented

### 1. Database Model
- **Model**: `BillOfLadingTemplate`
- **Location**: `CincyBarge_Development/dashboard/models.py`
- **Fields**:
  - `supplier` (OneToOne): Links template to a specific supplier
  - `template_file` (FileField): Stores the template file (PDF, DOCX, HTML, CSV, or XLSX)
  - `uploaded_at` (DateTime): Timestamp of upload
  - `uploaded_by` (ForeignKey): User who uploaded the template
  - `file_name` (CharField): Original filename
  - `description` (TextField): Optional notes about the template
  - `field_mapping` (JSONField): Stores field mappings for spreadsheet templates
  - `template_type` (CharField): Automatically set to 'document' or 'spreadsheet'

### 2. Form Validation
- **Form**: `BillOfLadingTemplateForm`
- **Location**: `CincyBarge_Development/dashboard/forms.py`
- **Validations**:
  - Accepts PDF, DOCX, HTML, CSV, and Excel (XLSX/XLS) files
  - Maximum file size: 10MB
  - Required fields: supplier and template file
  - Automatic template type detection based on file extension

### 3. Views and URLs
**Views** (`CincyBarge_Development/dashboard/views.py`):
- `bol()` - Main page displaying templates and upload form
- `upload_bol_template()` - Handles template uploads
- `delete_bol_template()` - Deletes a template
- `download_bol_template()` - Downloads a template file
- `view_template_fields()` - Field mapping interface for spreadsheet templates

**URLs** (`CincyBarge_Development/dashboard/urls.py`):
- `/bol/` - Bill of Lading management page
- `/bol/upload-template/` - Upload endpoint
- `/bol/delete-template/<id>/` - Delete endpoint
- `/bol/download-template/<id>/` - Download endpoint
- `/bol/field-mapping/<id>/` - Field mapping interface

### 4. User Interface
**Main Template** (`CincyBarge_Development/templates/dashboard/bol.html`):
- Upload form with supplier selection, file input, and description
- Table displaying all existing templates
- Visual file type indicators (PDF, DOCX, HTML, Excel)
- Spreadsheet badge for CSV/Excel templates
- Map Fields button for spreadsheet templates
- Download and delete actions for each template
- Confirmation modal for deletions
- Informational guide on how to use templates

**Field Mapping Interface** (`CincyBarge_Development/templates/dashboard/bol_field_mapping.html`):
- Interactive field mapping form
- Maps spreadsheet columns to system fields
- Template information display
- System fields reference guide
- Save and cancel options

### 5. Admin Interface
- Registered in Django Admin with custom configuration
- Displays template information with filters and search
- Shows upload history and related user information

## How to Use

### Uploading a Template
1. Navigate to the Bill of Lading page (`/bol/`)
2. Select a supplier from the dropdown
3. Choose a template file (PDF, DOCX, or HTML)
4. Optionally add a description
5. Click "Upload Template"

### Important Notes
- **One Template per Supplier**: Each supplier can have only one template. Uploading a new template for an existing supplier will replace the old one.
- **Supported Formats**: 
  - **Document Templates**: PDF, DOCX, HTML
  - **Spreadsheet Templates**: CSV, Excel (XLSX/XLS)
- **File Size Limit**: 10MB maximum
- **Storage Location**: Files are stored in `media/bol_templates/`
- **Field Mapping**: Required for spreadsheet templates to map columns to system fields

### Managing Templates
- **View**: All templates are displayed in a table on the BOL page
- **Map Fields** (Spreadsheet only): Click the blue map button to configure field mappings
- **Download**: Click the green download button to get a copy of the template
- **Delete**: Click the red delete button and confirm to remove a template

### Spreadsheet Field Mapping
For CSV and Excel templates, you can map the spreadsheet columns to system fields:

1. Upload your spreadsheet template
2. Click the "Map Fields" button (blue button with map icon)
3. Map each column header to a system field:
   - **Product Information**: product_name, quantity, weight, description, unit_price, total_value
   - **Shipping Information**: shipper_name, shipper_address, consignee_name, consignee_address, origin, destination
   - **Transport Details**: carrier, vessel_name, container_number, seal_number, freight_charges
   - **Administrative**: date, bill_number, notes
4. Save the mapping

The system will use these mappings when generating bills of lading from the template.

## Technical Details

### File Storage
- Templates are stored using Django's FileField
- Upload directory: `media/bol_templates/`
- Media URL: `/media/`
- Media root configured in settings

### Security
- Login required for all BOL-related views
- CSRF protection on all forms
- File type validation on upload
- File size restrictions enforced

### Database Migrations
- Migration file: `dashboard/migrations/0010_billofladingtemplate.py` - Initial model
- Migration file: `dashboard/migrations/0011_billofladingtemplate_field_mapping_and_more.py` - Added field mapping support
- Successfully applied to database in Docker environment

## Future Enhancements

Potential features for future development:
1. Template preview functionality
2. **Bill generation using uploaded templates with field mapping**
3. Template versioning/history
4. Bulk template uploads
5. Template variables/placeholders for dynamic content
6. **Integration with product data for automatic bill generation using mapped fields**
7. Export functionality for bills of lading
8. Google Sheets direct integration for real-time template updates
9. Excel formula support in templates
10. Custom field definitions beyond standard fields

## Testing

To test the implementation:
1. Start the Django development server
2. Log in to the application
3. Navigate to `/bol/`
4. Upload a sample template
5. Verify the template appears in the table
6. Test download functionality
7. Test delete functionality
8. Check Django Admin interface for the new model

## Files Modified/Created

### Modified Files
- `CincyBarge_Development/dashboard/models.py` - Added BillOfLadingTemplate model with field mapping support
- `CincyBarge_Development/dashboard/forms.py` - Added BillOfLadingTemplateForm with CSV/Excel support
- `CincyBarge_Development/dashboard/views.py` - Added BOL-related views including field mapping
- `CincyBarge_Development/dashboard/urls.py` - Added BOL URL patterns
- `CincyBarge_Development/dashboard/admin.py` - Registered new model
- `CincyBarge_Development/CincyBarge2Rail/settings.py` - Updated MEDIA_URL

### Created Files
- `CincyBarge_Development/templates/dashboard/bol.html` - BOL management UI
- `CincyBarge_Development/templates/dashboard/bol_field_mapping.html` - Field mapping interface
- `CincyBarge_Development/dashboard/migrations/0010_billofladingtemplate.py` - Initial database migration
- `CincyBarge_Development/dashboard/migrations/0011_billofladingtemplate_field_mapping_and_more.py` - Field mapping migration
- `CincyBarge_Development/BOL_TEMPLATE_FEATURE.md` - This documentation file

## Support

For issues or questions regarding this feature, please refer to the main project documentation or contact the development team.
