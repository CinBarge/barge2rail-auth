from django.contrib import admin
from .models import Product, Order, Supplier, RawProductData
from django.contrib.auth.models import Group

admin.site.site_header = 'Cincinatti Barge 2 Rail Dashboard'

class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'quantity', 'supplier')


class RawProductDataAdmin(admin.ModelAdmin):
    list_display = ('id', 'supplier', 'file_name', 'uploaded_by', 'uploaded_at')
    list_filter = ('supplier', 'uploaded_at')
    search_fields = ('file_name', 'supplier__name')
    readonly_fields = ('uploaded_at',)
    ordering = ('-uploaded_at',)


# Register your models here.

admin.site.register(Product, ProductAdmin)
admin.site.register(Order)
admin.site.register(Supplier)
admin.site.register(RawProductData, RawProductDataAdmin)
