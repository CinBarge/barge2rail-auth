from django import forms
from django.contrib import admin
from django.contrib.auth.models import Group

from .models import (
    BillOfLading,
    BillOfLadingLineItem,
    BillOfLadingTemplate,
    Order,
    Product,
    RawProductData,
    Supplier,
)

admin.site.site_header = "Cincinnati Barge 2 Rail Dashboard"
admin.site.site_title = "Barge2Rail Admin"
admin.site.index_title = "Dashboard Administration"


class AdminMediaMixin:
    """Mixin to add custom CSS to all admin classes"""

    class Media:
        css = {"all": ("admin/css/custom_admin.css",)}


@admin.register(Supplier)
class SupplierAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Supplier model"""

    list_display = ("id", "name", "product_count", "raw_data_count")
    search_fields = ("name",)
    list_per_page = 25
    ordering = ("name",)

    @admin.display(description="Products")
    def product_count(self, obj):
        """Display number of products for this supplier"""
        return obj.product_set.count()

    @admin.display(description="Raw Data Files")
    def raw_data_count(self, obj):
        """Display number of raw data entries for this supplier"""
        return obj.raw_data.count()


@admin.register(Product)
class ProductAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Product model"""

    list_display = ("id", "name", "quantity", "supplier", "order_count")
    list_filter = ("supplier",)
    search_fields = ("name", "supplier__name")
    list_per_page = 50
    ordering = ("name",)

    fieldsets = (
        ("Product Information", {"fields": ("name", "quantity")}),
        ("Supplier Details", {"fields": ("supplier",)}),
    )

    @admin.display(description="Orders")
    def order_count(self, obj):
        """Display number of orders for this product"""
        return obj.order_set.count()


@admin.register(Order)
class OrderAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Order model"""

    list_display = ("id", "product", "staff", "order_quantity", "date")
    list_filter = ("date", "staff", "product__supplier")
    search_fields = ("product__name", "staff__username", "staff__email")
    readonly_fields = ("date",)
    date_hierarchy = "date"
    list_per_page = 50
    ordering = ("-date",)

    fieldsets = (
        ("Order Details", {"fields": ("product", "order_quantity")}),
        ("Staff Information", {"fields": ("staff",)}),
        ("Timestamps", {"fields": ("date",), "classes": ("collapse",)}),
    )

    def get_queryset(self, request):
        """Optimize queries with select_related"""
        queryset = super().get_queryset(request)
        return queryset.select_related("product", "staff", "product__supplier")


@admin.register(RawProductData)
class RawProductDataAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Raw Product Data model"""

    list_display = (
        "id",
        "supplier",
        "file_name",
        "uploaded_by",
        "uploaded_at",
        "data_preview",
    )
    list_filter = ("supplier", "uploaded_at", "uploaded_by")
    search_fields = ("file_name", "supplier__name", "uploaded_by__username")
    readonly_fields = ("uploaded_at", "data_formatted")
    date_hierarchy = "uploaded_at"
    list_per_page = 25
    ordering = ("-uploaded_at",)

    fieldsets = (
        ("File Information", {"fields": ("file_name", "supplier")}),
        ("Upload Details", {"fields": ("uploaded_by", "uploaded_at")}),
        (
            "Data Content",
            {"fields": ("data", "data_formatted"), "classes": ("collapse",)},
        ),
    )

    @admin.display(description="Data Preview")
    def data_preview(self, obj):
        """Show a preview of the JSON data"""
        data_str = str(obj.data)
        return data_str[:50] + "..." if len(data_str) > 50 else data_str

    @admin.display(description="Formatted Data")
    def data_formatted(self, obj):
        """Display formatted JSON data for easy reading"""
        import json

        try:
            return json.dumps(obj.data, indent=2)
        except:
            return str(obj.data)

    def get_queryset(self, request):
        """Optimize queries with select_related"""
        queryset = super().get_queryset(request)
        return queryset.select_related("supplier", "uploaded_by")


@admin.register(BillOfLadingTemplate)
class BillOfLadingTemplateAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Bill of Lading Template model"""

    list_display = ("id", "supplier", "file_name", "uploaded_by", "uploaded_at")
    list_filter = ("supplier", "uploaded_at")
    search_fields = ("supplier__name", "file_name", "uploaded_by__username")
    readonly_fields = ("uploaded_at",)
    date_hierarchy = "uploaded_at"
    list_per_page = 25
    ordering = ("-uploaded_at",)


class BillOfLadingLineItemInline(admin.TabularInline):
    """Inline admin for BOL line items"""

    model = BillOfLadingLineItem
    extra = 0
    fields = ("product", "quantity", "weight", "description")
    readonly_fields = ("product", "quantity", "weight")


@admin.register(BillOfLading)
class BillOfLadingAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Bill of Lading model"""

    list_display = (
        "bill_number",
        "supplier",
        "status",
        "delivery_date",
        "created_by",
        "created_at",
    )
    list_filter = ("status", "supplier", "created_at", "delivery_date")
    search_fields = ("bill_number", "supplier__name", "destination", "origin")
    readonly_fields = (
        "bill_number",
        "created_at",
        "confirmed_at",
        "completed_at",
        "total_value",
    )
    date_hierarchy = "created_at"
    list_per_page = 25
    ordering = ("-created_at",)
    inlines = [BillOfLadingLineItemInline]

    fieldsets = (
        (
            "BOL Information",
            {"fields": ("bill_number", "supplier", "template", "status")},
        ),
        (
            "Shipping Details",
            {
                "fields": (
                    "shipper_name",
                    "shipper_address",
                    "consignee_name",
                    "consignee_address",
                    "origin",
                    "destination",
                )
            },
        ),
        (
            "Transport Details",
            {"fields": ("carrier", "vessel_name", "container_number", "seal_number")},
        ),
        ("Financial", {"fields": ("freight_charges", "total_value")}),
        (
            "Dates",
            {"fields": ("delivery_date", "created_at", "confirmed_at", "completed_at")},
        ),
        (
            "Additional Info",
            {"fields": ("notes", "created_by"), "classes": ("collapse",)},
        ),
    )


@admin.register(BillOfLadingLineItem)
class BillOfLadingLineItemAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Bill of Lading Line Item model"""

    list_display = ("id", "bill_of_lading", "product", "quantity", "weight")
    list_filter = ("bill_of_lading__supplier", "bill_of_lading__status")
    search_fields = ("bill_of_lading__bill_number", "product__name")
    list_per_page = 50
    ordering = ("-id",)


# Register models with their admin classes
