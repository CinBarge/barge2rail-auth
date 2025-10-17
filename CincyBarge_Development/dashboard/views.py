from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse, FileResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from .models import Product, Order, RawProductData, Supplier, BillOfLadingTemplate, BillOfLading, BillOfLadingLineItem
from .forms import BillOfLadingTemplateForm, BillOfLadingForm, BillOfLadingLineItemForm
from utilities.googlesheet import get_sheet_data, update_sheet_row, update_sheet_cell, sync_sheet_to_database
from urllib.parse import urlparse, parse_qs
from django.contrib import messages 
from datetime import date, datetime
import json
import csv
import io
from django.db import transaction

# Create your views here.

@login_required
def index(request):
    from datetime import datetime, timedelta
    from django.db.models import Q
    
    # Get today's date
    today = datetime.now().date()
    
    # Fetch today's orders and upcoming orders
    todays_orders = Order.objects.filter(date__date=today).select_related('product', 'bill_of_lading').order_by('-date')
    upcoming_orders = Order.objects.filter(date__date__gt=today).select_related('product', 'bill_of_lading').order_by('date')
    
    # Get scheduled deliveries (orders with delivery dates)
    scheduled_deliveries = Order.objects.filter(
        delivery_date__isnull=False,
        status__in=['pending', 'scheduled', 'in_progress']
    ).select_related('product', 'bill_of_lading', 'staff').order_by('delivery_date')
    
    # Get statistics for dashboard cards
    total_products = Product.objects.count()
    bols_draft = BillOfLading.objects.filter(status='draft')
    
    context = {
        'todays_orders': todays_orders,
        'upcoming_orders': upcoming_orders,
        'scheduled_deliveries': scheduled_deliveries,
        'today': today,
        'total_products': total_products,
        'bols_draft': bols_draft,
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
    
    # Unified inventory data list
    all_inventory_data = []
    all_columns = set()
    
    # Add structured Product data
    for product in products:
        product_data = {
            'supplier': product.supplier.name if product.supplier else 'N/A',
            'source': 'Structured',
            'data': {
                'name': product.name,
                'quantity': str(product.quantity) if product.quantity else '-',
            }
        }
        all_inventory_data.append(product_data)
        all_columns.update(product_data['data'].keys())
    
    # Get all raw data entries and merge them
    raw_data_entries = RawProductData.objects.select_related('supplier').all()
    
    for entry in raw_data_entries:
        data = entry.data
        
        # Handle CSV data (stored as {'rows': [...], 'total_rows': N})
        if isinstance(data, dict) and 'rows' in data:
            for row in data['rows']:
                unified_row = {
                    'supplier': entry.supplier.name,
                    'source': 'Uploaded',
                    'data': dict(row)
                }
                all_inventory_data.append(unified_row)
                all_columns.update(row.keys())
        
        # Handle JSON data (direct object or array)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    unified_row = {
                        'supplier': entry.supplier.name,
                        'source': 'Uploaded',
                        'data': dict(item)
                    }
                    all_inventory_data.append(unified_row)
                    all_columns.update(item.keys())
        elif isinstance(data, dict) and not 'rows' in data:
            # Single object
            unified_row = {
                'supplier': entry.supplier.name,
                'source': 'Uploaded',
                'data': dict(data)
            }
            all_inventory_data.append(unified_row)
            all_columns.update(data.keys())
    
    # Sort columns for consistent display
    sorted_columns = sorted(list(all_columns))

    context = {
        'suppliers': suppliers,
        'all_inventory_data': all_inventory_data,
        'all_columns': sorted_columns,
        'total_rows': len(all_inventory_data),
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
    """Main BOL page with template upload and BOL creation"""
    templates = BillOfLadingTemplate.objects.select_related('supplier', 'uploaded_by').all()
    bols_draft = BillOfLading.objects.filter(status='draft').select_related('supplier', 'created_by').order_by('-created_at')
    bols_confirmed = BillOfLading.objects.exclude(status='draft').select_related('supplier', 'created_by').order_by('-created_at')[:10]
    suppliers = Supplier.objects.all()
    
    template_form = BillOfLadingTemplateForm()
    
    context = {
        'templates': templates,
        'bols_draft': bols_draft,
        'bols_confirmed': bols_confirmed,
        'suppliers': suppliers,
        'template_form': template_form,
    }
    
    return render(request, 'dashboard/bol.html', context)

@login_required
@require_http_methods(["POST"])
def upload_bol_template(request):
    """Handle BOL template upload"""
    form = BillOfLadingTemplateForm(request.POST, request.FILES)
    
    if form.is_valid():
        template = form.save(commit=False)
        template.uploaded_by = request.user
        template.file_name = request.FILES['template_file'].name
        template.save()
        messages.success(request, f"Template uploaded successfully for {template.supplier.name}")
    else:
        for error in form.errors.values():
            messages.error(request, error)
    
    return redirect('dashboard-bol')

@login_required
def view_bol_template(request, template_id):
    """View/preview BOL template PDF"""
    template = get_object_or_404(BillOfLadingTemplate, id=template_id)
    
    try:
        return FileResponse(template.template_file.open('rb'), content_type='application/pdf')
    except Exception as e:
        messages.error(request, f"Error opening template: {str(e)}")
        return redirect('dashboard-bol')

@login_required
@require_http_methods(["POST"])
def delete_bol_template(request, template_id):
    """Delete BOL template"""
    template = get_object_or_404(BillOfLadingTemplate, id=template_id)
    supplier_name = template.supplier.name
    template.delete()
    messages.success(request, f"Template for {supplier_name} deleted successfully")
    return redirect('dashboard-bol')

@login_required
def create_bol(request):
    """Create a new Bill of Lading"""
    if request.method == 'POST':
        form = BillOfLadingForm(request.POST)
        if form.is_valid():
            bol = form.save(commit=False)
            bol.created_by = request.user
            
            # Generate unique bill number
            from datetime import datetime
            bill_number = f"BOL-{datetime.now().strftime('%Y%m%d')}-{BillOfLading.objects.count() + 1:04d}"
            bol.bill_number = bill_number
            
            # Try to link template
            try:
                template = BillOfLadingTemplate.objects.get(supplier=bol.supplier)
                bol.template = template
            except BillOfLadingTemplate.DoesNotExist:
                pass
            
            bol.save()
            messages.success(request, f"Bill of Lading {bill_number} created successfully")
            return redirect('dashboard-bol-edit', bol_id=bol.id)
    else:
        form = BillOfLadingForm()
    
    context = {
        'form': form,
    }
    return render(request, 'dashboard/bol_create.html', context)

@login_required
def edit_bol(request, bol_id):
    """Edit BOL and add products"""
    bol = get_object_or_404(BillOfLading, id=bol_id)
    
    if bol.status != 'draft':
        messages.warning(request, "This BOL has been confirmed and cannot be edited")
        return redirect('dashboard-bol')
    
    # Get products from the same supplier
    products = Product.objects.filter(supplier=bol.supplier)
    line_items = bol.line_items.select_related('product').all()
    
    context = {
        'bol': bol,
        'products': products,
        'line_items': line_items,
    }
    
    return render(request, 'dashboard/bol_edit.html', context)

@login_required
@require_http_methods(["POST"])
def add_product_to_bol(request, bol_id):
    """Add a product to the BOL"""
    bol = get_object_or_404(BillOfLading, id=bol_id)
    
    if bol.status != 'draft':
        return JsonResponse({'success': False, 'error': 'BOL is already confirmed'}, status=400)
    
    try:
        data = json.loads(request.body)
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)
        weight = data.get('weight')
        description = data.get('description', '')
        
        product = get_object_or_404(Product, id=product_id)
        
        # Create line item
        line_item = BillOfLadingLineItem.objects.create(
            bill_of_lading=bol,
            product=product,
            quantity=quantity,
            weight=weight or product.weight,
            description=description or product.description or ''
        )
        
        return JsonResponse({
            'success': True,
            'line_item': {
                'id': line_item.id,
                'product_name': product.name,
                'quantity': line_item.quantity,
                'weight': float(line_item.weight) if line_item.weight else 0,
                'description': line_item.description
            }
        })
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def remove_product_from_bol(request, bol_id, line_item_id):
    """Remove a product from the BOL"""
    bol = get_object_or_404(BillOfLading, id=bol_id)
    
    if bol.status != 'draft':
        return JsonResponse({'success': False, 'error': 'BOL is already confirmed'}, status=400)
    
    line_item = get_object_or_404(BillOfLadingLineItem, id=line_item_id, bill_of_lading=bol)
    line_item.delete()
    
    return JsonResponse({'success': True})

@login_required
def preview_bol(request, bol_id):
    """Preview BOL before confirmation"""
    bol = get_object_or_404(BillOfLading, id=bol_id)
    line_items = bol.line_items.select_related('product').all()
    
    total_weight = bol.calculate_total_weight()
    
    context = {
        'bol': bol,
        'line_items': line_items,
        'total_weight': total_weight,
    }
    
    return render(request, 'dashboard/bol_preview.html', context)

@login_required
@require_http_methods(["POST"])
def confirm_bol(request, bol_id):
    """Confirm BOL and create orders for scheduled delivery"""
    bol = get_object_or_404(BillOfLading, id=bol_id)
    
    if bol.status != 'draft':
        messages.warning(request, "This BOL has already been confirmed")
        return redirect('dashboard-bol')
    
    try:
        with transaction.atomic():
            # Update BOL status
            bol.status = 'confirmed'
            bol.confirmed_at = datetime.now()
            bol.save()
            
            # Create orders for each line item
            for line_item in bol.line_items.all():
                Order.objects.create(
                    product=line_item.product,
                    bill_of_lading=bol,
                    staff=request.user,
                    order_quantity=line_item.quantity,
                    delivery_date=bol.delivery_date,
                    status='scheduled'
                )
            
            messages.success(request, f"Bill of Lading {bol.bill_number} confirmed successfully! Orders have been scheduled.")
            return redirect('dashboard-index')
    except Exception as e:
        messages.error(request, f"Error confirming BOL: {str(e)}")
        return redirect('dashboard-bol-edit', bol_id=bol_id)

@login_required
def delete_bol(request, bol_id):
    """Delete a draft BOL"""
    bol = get_object_or_404(BillOfLading, id=bol_id)
    
    if bol.status != 'draft':
        messages.warning(request, "Only draft BOLs can be deleted")
        return redirect('dashboard-bol')
    
    bill_number = bol.bill_number
    bol.delete()
    messages.success(request, f"Bill of Lading {bill_number} deleted successfully")
    return redirect('dashboard-bol')

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


@login_required
def upload_raw_data(request):
    """Handle file upload for unstructured inventory data (CSV/JSON)."""
    if request.method == 'POST':
        # Check if creating a new supplier
        supplier_value = request.POST.get('supplier')
        new_supplier_name = request.POST.get('new_supplier_name', '').strip()
        
        if supplier_value == 'new' and new_supplier_name:
            # Create new supplier
            supplier, created = Supplier.objects.get_or_create(name=new_supplier_name)
            if created:
                messages.info(request, f"Created new supplier: {new_supplier_name}")
        elif supplier_value and supplier_value != 'new':
            # Use existing supplier
            try:
                supplier = Supplier.objects.get(id=supplier_value)
            except Supplier.DoesNotExist:
                messages.error(request, "Selected supplier does not exist.")
                return redirect('dashboard-product')
        else:
            messages.error(request, "Please select a supplier or enter a new supplier name.")
            return redirect('dashboard-product')
        
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            messages.error(request, "No file uploaded.")
            return redirect('dashboard-product')
            
        file_name = uploaded_file.name
        file_extension = file_name.split('.')[-1].lower()
        
        try:
            if file_extension == 'csv':
                # Parse CSV file
                decoded_file = uploaded_file.read().decode('utf-8')
                csv_reader = csv.DictReader(io.StringIO(decoded_file))
                
                # Convert CSV rows to list of dictionaries
                data_list = []
                for row in csv_reader:
                    # Store each row as a dictionary, preserving all fields
                    data_list.append(dict(row))
                
                # Store all rows as a single JSON object
                RawProductData.objects.create(
                    supplier=supplier,
                    data={'rows': data_list, 'total_rows': len(data_list)},
                    uploaded_by=request.user,
                    file_name=file_name
                )
                messages.success(request, f"Successfully uploaded {len(data_list)} rows from CSV file: {file_name}")
                
            elif file_extension == 'json':
                # Parse JSON file
                json_data = json.loads(uploaded_file.read().decode('utf-8'))
                
                # Store JSON data directly
                RawProductData.objects.create(
                    supplier=supplier,
                    data=json_data,
                    uploaded_by=request.user,
                    file_name=file_name
                )
                messages.success(request, f"Successfully uploaded JSON file: {file_name}")
            
            return redirect('dashboard-product')
            
        except Exception as e:
            messages.error(request, f"Error processing file: {str(e)}")
            return redirect('dashboard-product')
    else:
        return redirect('dashboard-product')


@login_required
def raw_data_view(request):
    """Display all raw inventory data uploads."""
    raw_data_entries = RawProductData.objects.select_related('supplier', 'uploaded_by').all()
    
    context = {
        'raw_data_entries': raw_data_entries,
    }
    
    return render(request, 'dashboard/raw_data.html', context)


@login_required
def raw_data_detail(request, pk):
    """View detailed data for a specific raw data entry."""
    try:
        raw_data = RawProductData.objects.select_related('supplier', 'uploaded_by').get(pk=pk)
        
        # Format the JSON data for display
        formatted_data = json.dumps(raw_data.data, indent=2)
        
        context = {
            'raw_data': raw_data,
            'formatted_data': formatted_data,
        }
        
        return render(request, 'dashboard/raw_data_detail.html', context)
    except RawProductData.DoesNotExist:
        messages.error(request, "Raw data entry not found.")
        return redirect('dashboard-raw-data')


@login_required
def raw_data_edit_list(request):
    """Display list of raw data entries for editing."""
    raw_data_entries = RawProductData.objects.select_related('supplier', 'uploaded_by').all().order_by('-uploaded_at')
    
    context = {
        'raw_data_entries': raw_data_entries,
    }
    
    return render(request, 'dashboard/raw_data_edit_list.html', context)


@login_required
def raw_data_edit(request, pk):
    """Edit a specific raw data entry."""
    try:
        raw_data = RawProductData.objects.select_related('supplier', 'uploaded_by').get(pk=pk)
        
        if request.method == 'POST':
            # Get updated data from form
            updated_data_str = request.POST.get('data')
            supplier_id = request.POST.get('supplier')
            
            try:
                # Parse the JSON data
                updated_data = json.loads(updated_data_str)
                
                # Update the raw data entry
                raw_data.data = updated_data
                if supplier_id:
                    raw_data.supplier_id = supplier_id
                raw_data.save()
                
                messages.success(request, f"Successfully updated raw data entry: {raw_data.file_name}")
                return redirect('raw-data-view')
                
            except json.JSONDecodeError as e:
                messages.error(request, f"Invalid JSON format: {str(e)}")
        
        # Format the JSON data for editing
        formatted_data = json.dumps(raw_data.data, indent=2)
        suppliers = Supplier.objects.all()
        
        context = {
            'raw_data': raw_data,
            'formatted_data': formatted_data,
            'suppliers': suppliers,
        }
        
        return render(request, 'dashboard/raw_data_edit.html', context)
        
    except RawProductData.DoesNotExist:
        messages.error(request, "Raw data entry not found.")
        return redirect('raw-data-edit-list')


@login_required
def raw_data_delete(request, pk):
    """Delete a specific raw data entry."""
    if request.method == 'POST':
        try:
            raw_data = RawProductData.objects.get(pk=pk)
            file_name = raw_data.file_name
            raw_data.delete()
            messages.success(request, f"Successfully deleted raw data entry: {file_name}")
        except RawProductData.DoesNotExist:
            messages.error(request, "Raw data entry not found.")
    
    return redirect('raw-data-view')
