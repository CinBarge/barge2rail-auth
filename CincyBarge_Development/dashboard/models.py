from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class Supplier(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name


class RawProductData(models.Model):
    """Store unstructured product data from CSV/JSON uploads"""
    supplier = models.ForeignKey(Supplier, on_delete=models.CASCADE, related_name='raw_data')
    data = models.JSONField(help_text="Unstructured product data stored as JSON")
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    file_name = models.CharField(max_length=255, blank=True)
    
    class Meta:
        verbose_name_plural = 'Raw Product Data'
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"{self.supplier.name} - {self.file_name} ({self.uploaded_at.strftime('%Y-%m-%d %H:%M')})"


class Product(models.Model):
    name = models.CharField(max_length=100, null=True)
    quantity = models.PositiveIntegerField(null=True)
    supplier = models.ForeignKey(Supplier, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return f'{self.name} - {self.quantity}'

    
    class Meta:
        verbose_name_plural = 'Product'
    
class Order(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, null=True)
    staff = models.ForeignKey(User, models.CASCADE, null=True)
    order_quantity = models.PositiveIntegerField(null=True)
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = 'Order'

    def __str__(self):
        return f'{self.product} ordered by {self.staff.username}'
