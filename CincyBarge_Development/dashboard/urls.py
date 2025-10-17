from django.urls import path
from . import views

urlpatterns = [
    path('dashboard/', views.index, name='dashboard-index'),
    path('staff/', views.staff, name='dashboard-staff'),
    path('product/', views.product, name='dashboard-product'),
    path('order/', views.order, name='dashboard-order'),
    path('bol/', views.bol, name='dashboard-bol'),
    # Google Sheets API endpoints
    path('api/sheet-products/', views.get_sheet_products, name='api-get-sheet-products'),
    path('api/update-sheet-row/', views.update_sheet_products, name='api-update-sheet-row'),
    path('api/update-sheet-cell/', views.update_sheet_cell, name='api-update-sheet-cell'),
    # Import Google Sheet to Database
    path('import-google-sheet/', views.import_google_sheet, name='import_google_sheet'),
    # Raw Inventory Data Upload & Management
    path('upload-raw-data/', views.upload_raw_data, name='upload-raw-data'),
    path('raw-data/', views.raw_data_view, name='raw-data-view'),
    path('raw-data/<int:pk>/', views.raw_data_detail, name='raw-data-detail'),
    path('raw-data/edit/', views.raw_data_edit_list, name='raw-data-edit-list'),
    path('raw-data/edit/<int:pk>/', views.raw_data_edit, name='raw-data-edit'),
    path('raw-data/delete/<int:pk>/', views.raw_data_delete, name='raw-data-delete'),
]
