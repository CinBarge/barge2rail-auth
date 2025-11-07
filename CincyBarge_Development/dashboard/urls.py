from django.urls import path

from . import views

urlpatterns = [
    path("dashboard/", views.index, name="dashboard-index"),
    path("staff/", views.staff, name="dashboard-staff"),
    path("product/", views.product, name="dashboard-product"),
    path("order/", views.order, name="dashboard-order"),
    path("order/edit/<int:order_id>/", views.edit_order, name="dashboard-order-edit"),
    path(
        "order/delete/<int:order_id>/",
        views.delete_order,
        name="dashboard-order-delete",
    ),
    path(
        "order/update-status/<int:order_id>/",
        views.update_order_status,
        name="dashboard-order-update-status",
    ),
    path("bol/", views.bol, name="dashboard-bol"),
    # BOL Creation and Management
    path("bol/create/", views.create_bol, name="dashboard-bol-create"),
    path("bol/edit/<int:bol_id>/", views.edit_bol, name="dashboard-bol-edit"),
    path(
        "bol/<int:bol_id>/add-product/",
        views.add_product_to_bol,
        name="dashboard-bol-add-product",
    ),
    path(
        "bol/<int:bol_id>/remove-product/<int:line_item_id>/",
        views.remove_product_from_bol,
        name="dashboard-bol-remove-product",
    ),
    path("bol/preview/<int:bol_id>/", views.preview_bol, name="dashboard-bol-preview"),
    path("bol/confirm/<int:bol_id>/", views.confirm_bol, name="dashboard-bol-confirm"),
    path("bol/delete/<int:bol_id>/", views.delete_bol, name="dashboard-bol-delete"),
    # BOL PDF Upload and Extraction
    path("bol/upload-pdf/", views.upload_bol_pdf, name="dashboard-bol-upload-pdf"),
    path(
        "bol/review-extracted/",
        views.review_extracted_bol,
        name="dashboard-bol-review-extracted",
    ),
    # Google Sheets API endpoints
    path(
        "api/sheet-products/", views.get_sheet_products, name="api-get-sheet-products"
    ),
    path(
        "api/update-sheet-row/",
        views.update_sheet_products,
        name="api-update-sheet-row",
    ),
    path(
        "api/update-sheet-cell/", views.update_sheet_cell, name="api-update-sheet-cell"
    ),
    # Import Google Sheet to Database
    path("import-google-sheet/", views.import_google_sheet, name="import_google_sheet"),
    # Raw Inventory Data Upload & Management
    path("upload-raw-data/", views.upload_raw_data, name="upload-raw-data"),
    path("raw-data/", views.raw_data_view, name="raw-data-view"),
    path("raw-data/<int:pk>/", views.raw_data_detail, name="raw-data-detail"),
    path("raw-data/edit/", views.raw_data_edit_list, name="raw-data-edit-list"),
    path("raw-data/edit/<int:pk>/", views.raw_data_edit, name="raw-data-edit"),
    path("raw-data/delete/<int:pk>/", views.raw_data_delete, name="raw-data-delete"),
    # Sync Raw Data to Products
    path("sync-raw-data/", views.sync_raw_data_to_products, name="sync-raw-data"),
]
