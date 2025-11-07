import csv
import io
import json
from datetime import date, datetime
from urllib.parse import parse_qs, urlparse

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.http import FileResponse, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods
from utilities.googlesheet import (
    get_sheet_data,
    sync_sheet_to_database,
    update_sheet_cell,
    update_sheet_row,
)
from utilities.pdf_extractor import extract_bol_from_pdf

from .forms import (
    BillOfLadingForm,
    BillOfLadingLineItemForm,
    BOLPDFUploadForm,
)
from .models import (
    BillOfLading,
    BillOfLadingLineItem,
    Order,
    Product,
    RawProductData,
    Supplier,
)

# Create your views here.


@login_required
def index(request):
    from datetime import datetime, timedelta

    from django.db.models import Q

    # Get today's date
    today = datetime.now().date()

    # Fetch today's orders and upcoming orders
    todays_orders = (
        Order.objects.filter(date__date=today)
        .select_related("product", "bill_of_lading")
        .order_by("-date")
    )
    upcoming_orders = (
        Order.objects.filter(date__date__gt=today)
        .select_related("product", "bill_of_lading")
        .order_by("date")
    )

    # Get scheduled deliveries (orders with delivery dates)
    scheduled_deliveries = (
        Order.objects.filter(
            delivery_date__isnull=False,
            status__in=["pending", "scheduled", "in_progress"],
        )
        .select_related("product", "bill_of_lading", "staff")
        .order_by("delivery_date")
    )

    # Get statistics for dashboard cards
    total_products = Product.objects.count()
    bols_draft = BillOfLading.objects.filter(status="draft")

    context = {
        "todays_orders": todays_orders,
        "upcoming_orders": upcoming_orders,
        "scheduled_deliveries": scheduled_deliveries,
        "today": today,
        "total_products": total_products,
        "bols_draft": bols_draft,
    }

    return render(request, "dashboard/index.html", context)


@login_required
def staff(request):
    return render(request, "dashboard/staff.html")


@login_required
def product(request):
    """Display products page with Google Sheets integration."""
    # Get products from database for the form

    if request.method == "POST":
        name = request.POST.get("name")
        quantity = request.POST.get("quantity")
        supplier_id = request.POST.get("supplier")

        # Validation (optional)
        if name and quantity and supplier_id:
            Product.objects.create(
                name=name, quantity=quantity, supplier_id=supplier_id
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
            "supplier": product.supplier.name if product.supplier else "N/A",
            "source": "Structured",
            "data": {
                "name": product.name,
                "quantity": str(product.quantity) if product.quantity else "-",
            },
        }
        all_inventory_data.append(product_data)
        all_columns.update(product_data["data"].keys())

    # Get all raw data entries and merge them
    raw_data_entries = RawProductData.objects.select_related("supplier").all()

    for entry in raw_data_entries:
        data = entry.data

        # Handle CSV data (stored as {'rows': [...], 'total_rows': N})
        if isinstance(data, dict) and "rows" in data:
            for row in data["rows"]:
                unified_row = {
                    "supplier": entry.supplier.name,
                    "source": "Uploaded",
                    "data": dict(row),
                }
                all_inventory_data.append(unified_row)
                all_columns.update(row.keys())

        # Handle JSON data (direct object or array)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    unified_row = {
                        "supplier": entry.supplier.name,
                        "source": "Uploaded",
                        "data": dict(item),
                    }
                    all_inventory_data.append(unified_row)
                    all_columns.update(item.keys())
        elif isinstance(data, dict) and not "rows" in data:
            # Single object
            unified_row = {
                "supplier": entry.supplier.name,
                "source": "Uploaded",
                "data": dict(data),
            }
            all_inventory_data.append(unified_row)
            all_columns.update(data.keys())

    # Sort columns for consistent display
    sorted_columns = sorted(list(all_columns))

    context = {
        "suppliers": suppliers,
        "all_inventory_data": all_inventory_data,
        "all_columns": sorted_columns,
        "total_rows": len(all_inventory_data),
    }

    return render(request, "dashboard/product.html", context)


@login_required
@require_http_methods(["GET"])
def get_sheet_products(request):
    """API endpoint to fetch Google Sheets data."""
    try:
        sheet_id = request.GET.get("sheet_id", None)
        range_name = request.GET.get("range", "Sheet1!A1:Z1000")

        data = get_sheet_data(sheet_id=sheet_id, range_name=range_name)

        return JsonResponse({"success": True, "data": data, "count": len(data)})
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def update_sheet_products(request):
    """API endpoint to update Google Sheets data."""
    try:
        data = json.loads(request.body)

        row_index = data.get("row_index")
        row_data = data.get("row_data")
        sheet_id = data.get("sheet_id", None)
        sheet_name = data.get("sheet_name", "Sheet1")

        if not row_index or not row_data:
            return JsonResponse(
                {
                    "success": False,
                    "error": "Missing required parameters: row_index and row_data",
                },
                status=400,
            )

        result = update_sheet_row(
            row_index=int(row_index),
            row_data=row_data,
            sheet_id=sheet_id,
            sheet_name=sheet_name,
        )

        return JsonResponse(result)
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON data"}, status=400
        )
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def update_sheet_cell(request):
    """API endpoint to update a single cell in Google Sheets."""
    try:
        data = json.loads(request.body)

        row_index = data.get("row_index")
        column = data.get("column")
        value = data.get("value")
        sheet_id = data.get("sheet_id", None)
        sheet_name = data.get("sheet_name", "Sheet1")

        if not all([row_index, column, value is not None]):
            return JsonResponse(
                {"success": False, "error": "Missing required parameters"}, status=400
            )

        from utilities.googlesheet import update_sheet_cell as update_cell_func

        result = update_cell_func(
            row_index=int(row_index),
            column=column,
            value=value,
            sheet_id=sheet_id,
            sheet_name=sheet_name,
        )

        return JsonResponse(result)
    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON data"}, status=400
        )
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@login_required
def order(request):
    from datetime import datetime

    # Get today's date
    today = datetime.now().date()

    # Fetch all orders
    all_orders = Order.objects.select_related(
        "product", "bill_of_lading", "staff"
    ).order_by("-date")
    todays_orders = all_orders.filter(date__date=today)
    upcoming_orders = all_orders.filter(date__date__gt=today)
    past_orders = all_orders.filter(date__date__lt=today)[:20]  # Last 20 past orders

    context = {
        "todays_orders": todays_orders,
        "upcoming_orders": upcoming_orders,
        "past_orders": past_orders,
        "today": today,
    }

    return render(request, "dashboard/order.html", context)


@login_required
def edit_order(request, order_id):
    """Edit an existing order"""
    order_obj = get_object_or_404(Order, id=order_id)

    # Only allow editing if order is not completed or cancelled
    if order_obj.status in ["completed", "cancelled"]:
        messages.warning(
            request, f"Cannot edit {order_obj.get_status_display()} orders"
        )
        return redirect("dashboard-order")

    if request.method == "POST":
        try:
            # Update order fields
            product_id = request.POST.get("product")
            if product_id:
                order_obj.product_id = product_id

            order_quantity = request.POST.get("order_quantity")
            if order_quantity:
                order_obj.order_quantity = int(order_quantity)

            delivery_date = request.POST.get("delivery_date")
            if delivery_date:
                order_obj.delivery_date = delivery_date

            status = request.POST.get("status")
            if status:
                order_obj.status = status
                # Set completed_at if status is completed
                if status == "completed" and not order_obj.completed_at:
                    order_obj.completed_at = datetime.now()

            order_obj.save()
            messages.success(request, f"Order #{order_obj.id} updated successfully")
            return redirect("dashboard-order")

        except Exception as e:
            messages.error(request, f"Error updating order: {str(e)}")

    # GET request - show edit form
    products = Product.objects.all().select_related("supplier").order_by("name")

    context = {
        "order": order_obj,
        "products": products,
        "status_choices": Order.STATUS_CHOICES,
    }

    return render(request, "dashboard/order_edit.html", context)


@login_required
@require_http_methods(["POST"])
def delete_order(request, order_id):
    """Delete an order"""
    order_obj = get_object_or_404(Order, id=order_id)

    # Only allow deleting if order is pending or scheduled
    if order_obj.status not in ["pending", "scheduled"]:
        messages.warning(
            request,
            f"Cannot delete {order_obj.get_status_display()} orders. Only pending/scheduled orders can be deleted.",
        )
        return redirect("dashboard-order")

    try:
        product_name = order_obj.product.name if order_obj.product else "Unknown"
        order_obj.delete()
        messages.success(request, f"Order for {product_name} deleted successfully")
    except Exception as e:
        messages.error(request, f"Error deleting order: {str(e)}")

    return redirect("dashboard-order")


@login_required
@require_http_methods(["POST"])
def update_order_status(request, order_id):
    """Quick update order status via AJAX"""
    order_obj = get_object_or_404(Order, id=order_id)

    try:
        data = json.loads(request.body)
        new_status = data.get("status")

        if new_status not in dict(Order.STATUS_CHOICES):
            return JsonResponse(
                {"success": False, "error": "Invalid status"}, status=400
            )

        order_obj.status = new_status

        # Set completed_at if status is completed
        if new_status == "completed" and not order_obj.completed_at:
            order_obj.completed_at = datetime.now()

        order_obj.save()

        return JsonResponse(
            {
                "success": True,
                "status": order_obj.get_status_display(),
                "completed_at": (
                    order_obj.completed_at.strftime("%Y-%m-%d %H:%M")
                    if order_obj.completed_at
                    else None
                ),
            }
        )

    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@login_required
def bol(request):
    """Main BOL page with BOL creation"""
    bols_draft = (
        BillOfLading.objects.filter(status="draft")
        .select_related("supplier", "created_by")
        .order_by("-created_at")
    )
    bols_confirmed = (
        BillOfLading.objects.exclude(status="draft")
        .select_related("supplier", "created_by")
        .order_by("-created_at")[:10]
    )
    suppliers = Supplier.objects.all()

    context = {
        "bols_draft": bols_draft,
        "bols_confirmed": bols_confirmed,
        "suppliers": suppliers,
    }

    return render(request, "dashboard/bol.html", context)


@login_required
def create_bol(request):
    """Create a new Bill of Lading"""
    if request.method == "POST":
        form = BillOfLadingForm(request.POST)
        if form.is_valid():
            bol = form.save(commit=False)
            bol.created_by = request.user

            # Generate unique bill number
            from datetime import datetime

            bill_number = f"BOL-{datetime.now().strftime('%Y%m%d')}-{BillOfLading.objects.count() + 1:04d}"
            bol.bill_number = bill_number

            bol.save()
            messages.success(
                request, f"Bill of Lading {bill_number} created successfully"
            )
            return redirect("dashboard-bol-edit", bol_id=bol.id)
    else:
        form = BillOfLadingForm()

    # Get all suppliers for the dropdown
    suppliers = Supplier.objects.all().order_by('name')

    context = {
        "form": form,
        "suppliers": suppliers,
    }
    return render(request, "dashboard/bol_create.html", context)


@login_required
def edit_bol(request, bol_id):
    """Edit BOL and add products"""
    bol = get_object_or_404(BillOfLading, id=bol_id)

    if bol.status != "draft":
        messages.warning(request, "This BOL has been confirmed and cannot be edited")
        return redirect("dashboard-bol")

    # Get ALL products from database with their suppliers for filtering
    products = Product.objects.all().select_related("supplier").order_by("name")
    line_items = bol.line_items.select_related("product").all()

    # Get unique suppliers for the filter dropdown
    suppliers = (
        Supplier.objects.filter(product__isnull=False).distinct().order_by("name")
    )

    context = {
        "bol": bol,
        "products": products,
        "line_items": line_items,
        "suppliers": suppliers,
    }

    return render(request, "dashboard/bol_edit.html", context)


@login_required
@require_http_methods(["POST"])
def add_product_to_bol(request, bol_id):
    """Add a product to the BOL"""
    bol = get_object_or_404(BillOfLading, id=bol_id)

    if bol.status != "draft":
        return JsonResponse(
            {"success": False, "error": "BOL is already confirmed"}, status=400
        )

    try:
        data = json.loads(request.body)
        product_id = data.get("product_id")
        quantity = data.get("quantity", 1)
        weight = data.get("weight")
        description = data.get("description", "")

        product = get_object_or_404(Product, id=product_id)

        # Create line item
        line_item = BillOfLadingLineItem.objects.create(
            bill_of_lading=bol,
            product=product,
            quantity=quantity,
            weight=weight or product.weight,
            description=description or product.description or "",
        )

        return JsonResponse(
            {
                "success": True,
                "line_item": {
                    "id": line_item.id,
                    "product_name": product.name,
                    "quantity": line_item.quantity,
                    "weight": float(line_item.weight) if line_item.weight else 0,
                    "description": line_item.description,
                },
            }
        )
    except Exception as e:
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def remove_product_from_bol(request, bol_id, line_item_id):
    """Remove a product from the BOL"""
    bol = get_object_or_404(BillOfLading, id=bol_id)

    if bol.status != "draft":
        return JsonResponse(
            {"success": False, "error": "BOL is already confirmed"}, status=400
        )

    line_item = get_object_or_404(
        BillOfLadingLineItem, id=line_item_id, bill_of_lading=bol
    )
    line_item.delete()

    return JsonResponse({"success": True})


@login_required
def preview_bol(request, bol_id):
    """Preview BOL before confirmation"""
    bol = get_object_or_404(BillOfLading, id=bol_id)
    line_items = bol.line_items.select_related("product").all()

    total_weight = bol.calculate_total_weight()

    context = {
        "bol": bol,
        "line_items": line_items,
        "total_weight": total_weight,
    }

    return render(request, "dashboard/bol_preview.html", context)


@login_required
@require_http_methods(["POST"])
def confirm_bol(request, bol_id):
    """Confirm BOL and create orders for scheduled delivery"""
    bol = get_object_or_404(BillOfLading, id=bol_id)

    if bol.status != "draft":
        messages.warning(request, "This BOL has already been confirmed")
        return redirect("dashboard-bol")

    try:
        with transaction.atomic():
            # Update BOL status
            bol.status = "confirmed"
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
                    status="scheduled",
                )

            messages.success(
                request,
                f"Bill of Lading {bol.bill_number} confirmed successfully! Orders have been scheduled.",
            )
            return redirect("dashboard-index")
    except Exception as e:
        messages.error(request, f"Error confirming BOL: {str(e)}")
        return redirect("dashboard-bol-edit", bol_id=bol_id)


@login_required
def delete_bol(request, bol_id):
    """Delete a draft BOL"""
    bol = get_object_or_404(BillOfLading, id=bol_id)

    if bol.status != "draft":
        messages.warning(request, "Only draft BOLs can be deleted")
        return redirect("dashboard-bol")

    bill_number = bol.bill_number
    bol.delete()
    messages.success(request, f"Bill of Lading {bill_number} deleted successfully")
    return redirect("dashboard-bol")


@login_required
@require_http_methods(["POST"])
def import_google_sheet(request):
    """Import products from a public Google Sheet into the database."""
    sheet_url = request.POST.get("sheet_url")

    if not sheet_url:
        messages.error(request, "No Google Sheet URL provided.")
        return redirect(request.headers.get("referer", "/"))

    try:
        # Extract the Sheet ID from the URL
        parsed_url = urlparse(sheet_url)
        path_parts = parsed_url.path.split("/")
        sheet_id = path_parts[path_parts.index("d") + 1]

        # Use default sheet name and range
        range_name = "Sheet1!A1:Z1000"

        # Fetch rows from Google Sheet
        rows = get_sheet_data(sheet_id=sheet_id, range_name=range_name)

        if not rows or len(rows) < 2:
            messages.warning(request, "Google Sheet is empty or missing header.")
            return redirect(request.headers.get("referer", "/"))

        headers = [h.strip().lower() for h in rows[0]]
        new_products = 0

        for row in rows[1:]:
            if not any(row):  # skip empty rows
                continue

            row_data = dict(zip(headers, row))

            name = row_data.get("name")
            quantity = row_data.get("quantity")
            supplier_name = row_data.get("supplier")

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

    return redirect(request.headers.get("referer", "/"))


@login_required
def upload_raw_data(request):
    """Handle file upload for unstructured inventory data (CSV/JSON)."""
    if request.method == "POST":
        # Check if creating a new supplier
        supplier_value = request.POST.get("supplier")
        new_supplier_name = request.POST.get("new_supplier_name", "").strip()

        if supplier_value == "new" and new_supplier_name:
            # Create new supplier
            supplier, created = Supplier.objects.get_or_create(name=new_supplier_name)
            if created:
                messages.info(request, f"Created new supplier: {new_supplier_name}")
        elif supplier_value and supplier_value != "new":
            # Use existing supplier
            try:
                supplier = Supplier.objects.get(id=supplier_value)
            except Supplier.DoesNotExist:
                messages.error(request, "Selected supplier does not exist.")
                return redirect("dashboard-product")
        else:
            messages.error(
                request, "Please select a supplier or enter a new supplier name."
            )
            return redirect("dashboard-product")

        uploaded_file = request.FILES.get("file")
        if not uploaded_file:
            messages.error(request, "No file uploaded.")
            return redirect("dashboard-product")

        file_name = uploaded_file.name
        file_extension = file_name.split(".")[-1].lower()

        try:
            if file_extension == "csv":
                # Parse CSV file
                decoded_file = uploaded_file.read().decode("utf-8")
                csv_reader = csv.DictReader(io.StringIO(decoded_file))

                # Convert CSV rows to list of dictionaries
                data_list = []
                for row in csv_reader:
                    # Store each row as a dictionary, preserving all fields
                    data_list.append(dict(row))

                # Store all rows as a single JSON object
                RawProductData.objects.create(
                    supplier=supplier,
                    data={"rows": data_list, "total_rows": len(data_list)},
                    uploaded_by=request.user,
                    file_name=file_name,
                )
                messages.success(
                    request,
                    f"Successfully uploaded {len(data_list)} rows from CSV file: {file_name}",
                )

            elif file_extension == "json":
                # Parse JSON file
                json_data = json.loads(uploaded_file.read().decode("utf-8"))

                # Store JSON data directly
                RawProductData.objects.create(
                    supplier=supplier,
                    data=json_data,
                    uploaded_by=request.user,
                    file_name=file_name,
                )
                messages.success(
                    request, f"Successfully uploaded JSON file: {file_name}"
                )

            return redirect("dashboard-product")

        except Exception as e:
            messages.error(request, f"Error processing file: {str(e)}")
            return redirect("dashboard-product")
    else:
        return redirect("dashboard-product")


@login_required
def raw_data_view(request):
    """Display all raw inventory data uploads."""
    raw_data_entries = RawProductData.objects.select_related(
        "supplier", "uploaded_by"
    ).all()

    context = {
        "raw_data_entries": raw_data_entries,
    }

    return render(request, "dashboard/raw_data.html", context)


@login_required
def raw_data_detail(request, pk):
    """View detailed data for a specific raw data entry."""
    try:
        raw_data = RawProductData.objects.select_related("supplier", "uploaded_by").get(
            pk=pk
        )

        # Format the JSON data for display
        formatted_data = json.dumps(raw_data.data, indent=2)

        context = {
            "raw_data": raw_data,
            "formatted_data": formatted_data,
        }

        return render(request, "dashboard/raw_data_detail.html", context)
    except RawProductData.DoesNotExist:
        messages.error(request, "Raw data entry not found.")
        return redirect("dashboard-raw-data")


@login_required
def raw_data_edit_list(request):
    """Display list of raw data entries for editing."""
    raw_data_entries = (
        RawProductData.objects.select_related("supplier", "uploaded_by")
        .all()
        .order_by("-uploaded_at")
    )

    context = {
        "raw_data_entries": raw_data_entries,
    }

    return render(request, "dashboard/raw_data_edit_list.html", context)


@login_required
def raw_data_edit(request, pk):
    """Edit a specific raw data entry."""
    try:
        raw_data = RawProductData.objects.select_related("supplier", "uploaded_by").get(
            pk=pk
        )

        if request.method == "POST":
            # Get updated data from form
            updated_data_str = request.POST.get("data")
            supplier_id = request.POST.get("supplier")

            try:
                # Parse the JSON data
                updated_data = json.loads(updated_data_str)

                # Update the raw data entry
                raw_data.data = updated_data
                if supplier_id:
                    raw_data.supplier_id = supplier_id
                raw_data.save()

                messages.success(
                    request,
                    f"Successfully updated raw data entry: {raw_data.file_name}",
                )
                return redirect("raw-data-view")

            except json.JSONDecodeError as e:
                messages.error(request, f"Invalid JSON format: {str(e)}")

        # Format the JSON data for editing
        formatted_data = json.dumps(raw_data.data, indent=2)
        suppliers = Supplier.objects.all()

        context = {
            "raw_data": raw_data,
            "formatted_data": formatted_data,
            "suppliers": suppliers,
        }

        return render(request, "dashboard/raw_data_edit.html", context)

    except RawProductData.DoesNotExist:
        messages.error(request, "Raw data entry not found.")
        return redirect("raw-data-edit-list")


@login_required
def raw_data_delete(request, pk):
    """Delete a specific raw data entry."""
    if request.method == "POST":
        try:
            raw_data = RawProductData.objects.get(pk=pk)
            file_name = raw_data.file_name
            raw_data.delete()
            messages.success(
                request, f"Successfully deleted raw data entry: {file_name}"
            )
        except RawProductData.DoesNotExist:
            messages.error(request, "Raw data entry not found.")

    return redirect("raw-data-view")


@login_required
@require_http_methods(["POST"])
def sync_raw_data_to_products(request):
    """Sync RawProductData entries to Product table"""
    try:
        synced_count = 0
        skipped_count = 0
        error_count = 0
        error_details = []

        # Get all raw data entries
        raw_data_entries = RawProductData.objects.select_related("supplier").all()

        for entry in raw_data_entries:
            data = entry.data
            supplier = entry.supplier

            # Handle CSV data (stored as {'rows': [...], 'total_rows': N})
            if isinstance(data, dict) and "rows" in data:
                for idx, row in enumerate(data["rows"]):
                    try:
                        # Extract product info from row - support multiple field name variations
                        # Primary identifiers for product name
                        name = (
                            row.get("PARTNBR")
                            or row.get("partnbr")
                            or row.get("Part Number")
                            or row.get("name")
                            or row.get("Name")
                            or row.get("product")
                            or row.get("Product")
                            or row.get("TAGNBR")
                            or row.get("TAG")
                            or row.get("Item Code")
                            or row.get("SKU")
                        )

                        # Quantity fields
                        quantity = (
                            row.get("COIL")
                            or row.get("coil")
                            or row.get("quantity")
                            or row.get("Quantity")
                            or row.get("qty")
                            or row.get("Qty")
                            or 1
                        )

                        # Weight fields
                        weight = (
                            row.get("COILWEIG")
                            or row.get("weight")
                            or row.get("Weight")
                            or row.get("lbs")
                            or row.get("Lbs")
                            or None
                        )

                        # Description fields
                        description = (
                            row.get("SPEC")
                            or row.get("spec")
                            or row.get("NOTES")
                            or row.get("notes")
                            or row.get("description")
                            or row.get("Description")
                            or ""
                        )

                        if not name:
                            skipped_count += 1
                            continue

                        # Convert quantity to int if it's a string (remove commas first)
                        if isinstance(quantity, str):
                            quantity = (
                                int(quantity.replace(",", ""))
                                if quantity.strip()
                                else 1
                            )

                        # Convert weight to float if it's a string (remove commas first)
                        if isinstance(weight, str):
                            weight = (
                                float(weight.replace(",", ""))
                                if weight.strip()
                                else None
                            )

                        # Create or update product
                        product, created = Product.objects.update_or_create(
                            name=str(name)[:200],  # Limit name length
                            supplier=supplier,
                            defaults={
                                "quantity": int(quantity) if quantity else 1,
                                "weight": float(weight) if weight else None,
                                "description": (
                                    str(description)[:500] if description else ""
                                ),
                            },
                        )
                        synced_count += 1
                    except Exception as e:
                        error_count += 1
                        if len(error_details) < 5:  # Capture first 5 errors
                            error_details.append(f"Row {idx}: {str(e)}")
                        continue

            # Handle JSON data (direct object or array)
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        try:
                            # Support multiple field name variations
                            name = (
                                item.get("PARTNBR")
                                or item.get("partnbr")
                                or item.get("Part Number")
                                or item.get("name")
                                or item.get("Name")
                                or item.get("product")
                                or item.get("Product")
                                or item.get("TAGNBR")
                                or item.get("TAG")
                                or item.get("Item Code")
                                or item.get("SKU")
                            )

                            quantity = (
                                item.get("COIL")
                                or item.get("coil")
                                or item.get("quantity")
                                or item.get("Quantity")
                                or item.get("qty")
                                or item.get("Qty")
                                or 1
                            )

                            weight = (
                                item.get("COILWEIG")
                                or item.get("weight")
                                or item.get("Weight")
                                or item.get("lbs")
                                or item.get("Lbs")
                                or None
                            )

                            description = (
                                item.get("SPEC")
                                or item.get("spec")
                                or item.get("NOTES")
                                or item.get("notes")
                                or item.get("description")
                                or item.get("Description")
                                or ""
                            )

                            if not name:
                                skipped_count += 1
                                continue

                            product, created = Product.objects.update_or_create(
                                name=str(name)[:200],
                                supplier=supplier,
                                defaults={
                                    "quantity": int(quantity) if quantity else 1,
                                    "weight": float(weight) if weight else None,
                                    "description": (
                                        str(description)[:500] if description else ""
                                    ),
                                },
                            )
                            synced_count += 1
                        except Exception as e:
                            error_count += 1
                            continue

            elif isinstance(data, dict) and "rows" not in data:
                # Single object
                try:
                    # Support multiple field name variations
                    name = (
                        data.get("PARTNBR")
                        or data.get("partnbr")
                        or data.get("Part Number")
                        or data.get("name")
                        or data.get("Name")
                        or data.get("product")
                        or data.get("Product")
                        or data.get("TAGNBR")
                        or data.get("TAG")
                        or data.get("Item Code")
                        or data.get("SKU")
                    )

                    quantity = (
                        data.get("COIL")
                        or data.get("coil")
                        or data.get("quantity")
                        or data.get("Quantity")
                        or data.get("qty")
                        or data.get("Qty")
                        or 1
                    )

                    weight = (
                        data.get("COILWEIG")
                        or data.get("weight")
                        or data.get("Weight")
                        or data.get("lbs")
                        or data.get("Lbs")
                        or None
                    )

                    description = (
                        data.get("SPEC")
                        or data.get("spec")
                        or data.get("NOTES")
                        or data.get("notes")
                        or data.get("description")
                        or data.get("Description")
                        or ""
                    )

                    if name:
                        product, created = Product.objects.update_or_create(
                            name=str(name)[:200],
                            supplier=supplier,
                            defaults={
                                "quantity": int(quantity) if quantity else 1,
                                "weight": float(weight) if weight else None,
                                "description": (
                                    str(description)[:500] if description else ""
                                ),
                            },
                        )
                        synced_count += 1
                    else:
                        skipped_count += 1
                except Exception as e:
                    error_count += 1

        message = f"Sync complete! {synced_count} products synced"
        if skipped_count > 0:
            message += f", {skipped_count} skipped (missing name)"
        if error_count > 0:
            message += f", {error_count} errors"
            if error_details:
                messages.error(request, "Sample errors: " + "; ".join(error_details))

        if synced_count > 0:
            messages.success(request, message)
        else:
            messages.warning(request, message)
    except Exception as e:
        messages.error(request, f"Error during sync: {str(e)}")

    return redirect("dashboard-product")


@login_required
def upload_bol_pdf(request):
    """Upload BOL PDF and extract data for review"""
    if request.method == "POST":
        form = BOLPDFUploadForm(request.POST, request.FILES)

        if form.is_valid():
            supplier = form.cleaned_data["supplier"]
            pdf_file = request.FILES["pdf_file"]

            try:
                # Extract data from PDF
                extracted_data = extract_bol_from_pdf(pdf_file)

                # Store extracted data in session for review
                request.session["extracted_bol_data"] = {
                    "supplier_id": supplier.id,
                    "supplier_name": supplier.name,
                    "pdf_filename": pdf_file.name,
                    **extracted_data,
                }

                messages.success(
                    request,
                    f"Successfully extracted data from {pdf_file.name}. Please review and correct if needed.",
                )
                return redirect("dashboard-bol-review-extracted")

            except Exception as e:
                messages.error(request, f"Error extracting PDF data: {str(e)}")
                return redirect("dashboard-bol")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
            return redirect("dashboard-bol")

    # GET request - show upload form
    form = BOLPDFUploadForm()
    context = {
        "form": form,
    }
    return render(request, "dashboard/bol_pdf_upload.html", context)


@login_required
def review_extracted_bol(request):
    """Review and edit extracted BOL data before saving"""
    extracted_data = request.session.get("extracted_bol_data")

    if not extracted_data:
        messages.warning(
            request, "No extracted data found. Please upload a BOL PDF first."
        )
        return redirect("dashboard-bol")

    # Get all available products (not filtered by supplier)
    # This allows adding any product to the BOL
    available_products = (
        Product.objects.all().select_related("supplier").order_by("name")
    )

    if request.method == "POST":
        try:
            with transaction.atomic():
                # Get supplier
                supplier = get_object_or_404(Supplier, id=extracted_data["supplier_id"])

                # Create BOL with reviewed data
                from datetime import datetime

                bill_number = (
                    request.POST.get("bill_number")
                    or f"BOL-{datetime.now().strftime('%Y%m%d')}-{BillOfLading.objects.count() + 1:04d}"
                )

                bol = BillOfLading.objects.create(
                    bill_number=bill_number,
                    supplier=supplier,
                    shipper_name=request.POST.get("shipper_name", ""),
                    shipper_address=request.POST.get("shipper_address", ""),
                    consignee_name=request.POST.get("consignee_name", ""),
                    consignee_address=request.POST.get("consignee_address", ""),
                    origin=request.POST.get("origin", ""),
                    destination=request.POST.get("destination", ""),
                    carrier=request.POST.get("carrier", ""),
                    vessel_name=request.POST.get("vessel_name", ""),
                    container_number=request.POST.get("container_number", ""),
                    seal_number=request.POST.get("seal_number", ""),
                    freight_charges=request.POST.get("freight_charges") or None,
                    delivery_date=request.POST.get("delivery_date") or None,
                    notes=request.POST.get("notes", ""),
                    status="draft",
                    created_by=request.user,
                )

                # Create line items from extracted PDF data
                line_items_data = extracted_data.get("line_items", [])
                for i, item_data in enumerate(line_items_data):
                    # Check if user wants to include this line item
                    include_item = request.POST.get(f"include_item_{i}")
                    if include_item == "on":
                        # Try to find matching product or create new one
                        description = request.POST.get(
                            f"item_description_{i}", item_data.get("description", "")
                        )
                        quantity = request.POST.get(
                            f"item_quantity_{i}", item_data.get("quantity", 1)
                        )
                        weight = request.POST.get(
                            f"item_weight_{i}", item_data.get("weight", 0)
                        )

                        # Try to find or create product
                        product_name = (
                            description[:100] if description else f"Item {i+1}"
                        )
                        product, created = Product.objects.get_or_create(
                            name=product_name,
                            supplier=supplier,
                            defaults={
                                "quantity": int(quantity) if quantity else 1,
                                "description": description,
                                "weight": float(weight) if weight else None,
                            },
                        )

                        # Create line item
                        BillOfLadingLineItem.objects.create(
                            bill_of_lading=bol,
                            product=product,
                            quantity=int(quantity) if quantity else 1,
                            weight=float(weight) if weight else None,
                            description=description,
                        )

                # Add products selected from database
                for product in available_products:
                    add_product_key = f"add_product_{product.id}"
                    if request.POST.get(add_product_key):
                        quantity = request.POST.get(
                            f"add_product_qty_{product.id}", product.quantity
                        )
                        weight = request.POST.get(
                            f"add_product_weight_{product.id}", product.weight
                        )

                        # Create line item for this product
                        BillOfLadingLineItem.objects.create(
                            bill_of_lading=bol,
                            product=product,
                            quantity=int(quantity) if quantity else 1,
                            weight=float(weight) if weight else product.weight,
                            description=product.description or "",
                        )

                # Clear session data
                del request.session["extracted_bol_data"]

                messages.success(
                    request,
                    f"Bill of Lading {bill_number} created successfully from PDF!",
                )
                return redirect("dashboard-bol-edit", bol_id=bol.id)

        except Exception as e:
            messages.error(request, f"Error creating BOL: {str(e)}")
            return redirect("dashboard-bol-review-extracted")

    # GET request - show review form
    context = {
        "extracted_data": extracted_data,
        "available_products": available_products,
    }
    return render(request, "dashboard/bol_review_extracted.html", context)
