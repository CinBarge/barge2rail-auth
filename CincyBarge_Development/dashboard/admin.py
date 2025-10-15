from django.contrib import admin
from .models import Product, Order, Supplier, RawProductData
from django.contrib.auth.models import Group
from django import forms

admin.site.site_header = 'Cincinnati Barge 2 Rail Dashboard'
admin.site.site_title = 'Barge2Rail Admin'
admin.site.index_title = 'Dashboard Administration'


class AdminMediaMixin:
    """Mixin to add custom CSS to all admin classes"""
    class Media:
        css = {
            'all': ('admin/css/custom_admin.css',)
        }


class SupplierAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Supplier model"""
    list_display = ('id', 'name', 'product_count', 'raw_data_count')
    search_fields = ('name',)
    list_per_page = 25
    ordering = ('name',)
    
    def product_count(self, obj):
        """Display number of products for this supplier"""
        return obj.product_set.count()
    product_count.short_description = 'Products'
    
    def raw_data_count(self, obj):
        """Display number of raw data entries for this supplier"""
        return obj.raw_data.count()
    raw_data_count.short_description = 'Raw Data Files'


class ProductAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Product model"""
    list_display = ('id', 'name', 'quantity', 'supplier', 'order_count')
    list_filter = ('supplier',)
    search_fields = ('name', 'supplier__name')
    list_per_page = 50
    ordering = ('name',)
    
    fieldsets = (
        ('Product Information', {
            'fields': ('name', 'quantity')
        }),
        ('Supplier Details', {
            'fields': ('supplier',)
        }),
    )
    
    def order_count(self, obj):
        """Display number of orders for this product"""
        return obj.order_set.count()
    order_count.short_description = 'Orders'


class OrderAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Order model"""
    list_display = ('id', 'product', 'staff', 'order_quantity', 'date')
    list_filter = ('date', 'staff', 'product__supplier')
    search_fields = ('product__name', 'staff__username', 'staff__email')
    readonly_fields = ('date',)
    date_hierarchy = 'date'
    list_per_page = 50
    ordering = ('-date',)
    
    fieldsets = (
        ('Order Details', {
            'fields': ('product', 'order_quantity')
        }),
        ('Staff Information', {
            'fields': ('staff',)
        }),
        ('Timestamps', {
            'fields': ('date',),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        """Optimize queries with select_related"""
        queryset = super().get_queryset(request)
        return queryset.select_related('product', 'staff', 'product__supplier')


class RawProductDataAdmin(AdminMediaMixin, admin.ModelAdmin):
    """Admin configuration for Raw Product Data model"""
    list_display = ('id', 'supplier', 'file_name', 'uploaded_by', 'uploaded_at', 'data_preview')
    list_filter = ('supplier', 'uploaded_at', 'uploaded_by')
    search_fields = ('file_name', 'supplier__name', 'uploaded_by__username')
    readonly_fields = ('uploaded_at', 'data_formatted')
    date_hierarchy = 'uploaded_at'
    list_per_page = 25
    ordering = ('-uploaded_at',)
    
    fieldsets = (
        ('File Information', {
            'fields': ('file_name', 'supplier')
        }),
        ('Upload Details', {
            'fields': ('uploaded_by', 'uploaded_at')
        }),
        ('Data Content', {
            'fields': ('data', 'data_formatted'),
            'classes': ('collapse',)
        }),
    )
    
    def data_preview(self, obj):
        """Show a preview of the JSON data"""
        data_str = str(obj.data)
        return data_str[:50] + '...' if len(data_str) > 50 else data_str
    data_preview.short_description = 'Data Preview'
    
    def data_formatted(self, obj):
        """Display formatted JSON data for easy reading"""
        import json
        try:
            return json.dumps(obj.data, indent=2)
        except:
            return str(obj.data)
    data_formatted.short_description = 'Formatted Data'
    
    def get_queryset(self, request):
        """Optimize queries with select_related"""
        queryset = super().get_queryset(request)
        return queryset.select_related('supplier', 'uploaded_by')


# Register models with their admin classes
admin.site.register(Product, ProductAdmin)
admin.site.register(Order, OrderAdmin)
admin.site.register(Supplier, SupplierAdmin)
admin.site.register(RawProductData, RawProductDataAdmin)
