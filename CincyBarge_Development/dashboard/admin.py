from django.contrib import admin
from .models import Product, Order, Supplier
from django.contrib.auth.models import Group

admin.site.site_header = 'Cincinatti Barge 2 Rail Dashboard'

class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'quantity', 'category')
    list_filter = ['category']

# Register your models here.

admin.site.register(Product, ProductAdmin)
admin.site.register(Order)
admin.site.register(Supplier)