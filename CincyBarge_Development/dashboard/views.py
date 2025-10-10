from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from .models import Product, Order
from utilities.googlesheet import get_sheet_data, update_sheet_row, update_sheet_cell, sync_sheet_to_database
from urllib.parse import urlparse, parse_qs
from django.contrib import messages 
from datetime import date
from .models import Supplier
import json

# Create your views here.

@login_required
def index(request):
    from datetime import datetime, timedelta
    from django.db.models import Q
    
    # Get today's date
    today = datetime.now().date()
    
    # Fetch today's orders and upcoming orders
    todays_orders = Order.objects.filter(date__date=today).order_by('-date')
    upcoming_orders = Order.objects.filter(date__date__gt=today).order_by('date')
    
    context = {
        'todays_orders': todays_orders,
        'upcoming_orders': upcoming_orders,
        'today': today,
    }
    
    return render(request, 'dashboard/index.html', context)

@login_required
def staff(request): 
    return render(request, 'dashboard/staff.html')

@login_required
def product(request):
    """Display products page with Google Sheets integration."""
    # Get products from database for the form

    if request.method == "POST":
        name = request.POST.get('name')
        quantity = request.POST.get('quantity')
        supplier_id = request.POST.get('supplier') 

        # Validation (optional)
        if name and quantity and supplier_id:
            Product.objects.create(
                name=name,
                quantity=quantity,
                supplier_id=supplier_id  
            )
    
    # Prepare form data for display
    products = Product.objects.all()
    suppliers = Supplier.objects.all()

    context = {
        'product': products,
        'suppliers': suppliers,
    }
    
    return render(request, 'dashboard/product.html', context)

@login_required
@require_http_methods(["GET"])
def get_sheet_products(request):
    """API endpoint to fetch Google Sheets data."""
    try:
        sheet_id = request.GET.get('sheet_id', None)
        range_name = request.GET.get('range', 'Sheet1!A1:Z1000')
        
        data = get_sheet_data(sheet_id=sheet_id, range_name=range_name)
        
        return JsonResponse({
            'success': True,
            'data': data,
            'count': len(data)
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def update_sheet_products(request):
    """API endpoint to update Google Sheets data."""
    try:
        data = json.loads(request.body)
        
        row_index = data.get('row_index')
        row_data = data.get('row_data')
        sheet_id = data.get('sheet_id', None)
        sheet_name = data.get('sheet_name', 'Sheet1')
        
        if not row_index or not row_data:
            return JsonResponse({
                'success': False,
                'error': 'Missing required parameters: row_index and row_data'
            }, status=400)
        
        result = update_sheet_row(
            row_index=int(row_index),
            row_data=row_data,
            sheet_id=sheet_id,
            sheet_name=sheet_name
        )
        
        return JsonResponse(result)
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
@require_http_methods(["POST"])
def update_sheet_cell(request):
    """API endpoint to update a single cell in Google Sheets."""
    try:
        data = json.loads(request.body)
        
        row_index = data.get('row_index')
        column = data.get('column')
        value = data.get('value')
        sheet_id = data.get('sheet_id', None)
        sheet_name = data.get('sheet_name', 'Sheet1')
        
        if not all([row_index, column, value is not None]):
            return JsonResponse({
                'success': False,
                'error': 'Missing required parameters'
            }, status=400)
        
        from utilities.googlesheet import update_sheet_cell as update_cell_func
        result = update_cell_func(
            row_index=int(row_index),
            column=column,
            value=value,
            sheet_id=sheet_id,
            sheet_name=sheet_name
        )
        
        return JsonResponse(result)
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)

@login_required
def order(request):
    from datetime import datetime
    
    # Get today's date
    today = datetime.now().date()
    
    # Fetch today's orders and upcoming orders
    todays_orders = Order.objects.filter(date__date=today).order_by('-date')
    upcoming_orders = Order.objects.filter(date__date__gt=today).order_by('date')
    
    context = {
        'todays_orders': todays_orders,
        'upcoming_orders': upcoming_orders,
        'today': today,
    }
    
    return render(request, 'dashboard/order.html', context)

@login_required
def bol(request):
    return render(request, 'dashboard/bol.html')

@login_required
@require_http_methods(["POST"])
def import_google_sheet(request):
    """Import products from a public Google Sheet into the database."""
    sheet_url = request.POST.get('sheet_url')

    if not sheet_url:
        messages.error(request, "No Google Sheet URL provided.")
        return redirect(request.META.get('HTTP_REFERER', '/'))

    try:
        # Extract the Sheet ID from the URL
        parsed_url = urlparse(sheet_url)
        path_parts = parsed_url.path.split('/')
        sheet_id = path_parts[path_parts.index('d') + 1]

        # Use default sheet name and range
        range_name = 'Sheet1!A1:Z1000'

        # Fetch rows from Google Sheet
        rows = get_sheet_data(sheet_id=sheet_id, range_name=range_name)

        if not rows or len(rows) < 2:
            messages.warning(request, "Google Sheet is empty or missing header.")
            return redirect(request.META.get('HTTP_REFERER', '/'))

        headers = [h.strip().lower() for h in rows[0]]
        new_products = 0

        for row in rows[1:]:
            if not any(row):  # skip empty rows
                continue

            row_data = dict(zip(headers, row))

            name = row_data.get('name')
            quantity = row_data.get('quantity')
            supplier_name = row_data.get('supplier')

            if not all([name, quantity, supplier_name]):
                continue  # skip incomplete rows

            # Get or create supplier
            supplier, _ = Supplier.objects.get_or_create(name=supplier_name)

            # Create product
            Product.objects.create(
                name=name,
                quantity=int(quantity),
                supplier=supplier,
            )
            new_products += 1

        messages.success(request, f"Successfully imported {new_products} products.")
    except Exception as e:
        messages.error(request, f"Error during import: {str(e)}")

    return redirect(request.META.get('HTTP_REFERER', '/'))
