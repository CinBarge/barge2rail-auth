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
]
