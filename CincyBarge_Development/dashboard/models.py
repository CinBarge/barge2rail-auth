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
    description = models.TextField(blank=True, null=True)
    weight = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True, help_text="Weight in lbs")

    def __str__(self):
        return f'{self.name} - {self.quantity}'

    
    class Meta:
        verbose_name_plural = 'Product'


class BillOfLadingTemplate(models.Model):
    """Store PDF templates for Bill of Lading"""
    supplier = models.OneToOneField(Supplier, on_delete=models.CASCADE, related_name='bol_template')
    template_file = models.FileField(upload_to='bol_templates/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    file_name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    
    class Meta:
        verbose_name_plural = 'Bill of Lading Templates'
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"BOL Template - {self.supplier.name}"


class BillOfLading(models.Model):
    """Store generated Bill of Lading documents"""
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('confirmed', 'Confirmed'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    bill_number = models.CharField(max_length=50, unique=True)
    supplier = models.ForeignKey(Supplier, on_delete=models.PROTECT)
    template = models.ForeignKey(BillOfLadingTemplate, on_delete=models.SET_NULL, null=True, blank=True)
    
    # Shipping details
    shipper_name = models.CharField(max_length=255, blank=True)
    shipper_address = models.TextField(blank=True)
    consignee_name = models.CharField(max_length=255, blank=True)
    consignee_address = models.TextField(blank=True)
    origin = models.CharField(max_length=255, blank=True)
    destination = models.CharField(max_length=255, blank=True)
    
    # Transport details
    carrier = models.CharField(max_length=255, blank=True)
    vessel_name = models.CharField(max_length=255, blank=True)
    container_number = models.CharField(max_length=100, blank=True)
    seal_number = models.CharField(max_length=100, blank=True)
    
    # Financial
    freight_charges = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    total_value = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    # Status and dates
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='created_bols')
    confirmed_at = models.DateTimeField(null=True, blank=True)
    delivery_date = models.DateField(null=True, blank=True, help_text="Expected delivery date")
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # PDF storage
    pdf_file = models.FileField(upload_to='generated_bols/', null=True, blank=True)
    
    notes = models.TextField(blank=True)
    
    class Meta:
        verbose_name_plural = 'Bills of Lading'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"BOL #{self.bill_number} - {self.supplier.name}"
    
    def calculate_total_weight(self):
        """Calculate total weight from line items"""
        total = sum(item.weight or 0 for item in self.line_items.all())
        return total


class BillOfLadingLineItem(models.Model):
    """Individual line items in a Bill of Lading"""
    bill_of_lading = models.ForeignKey(BillOfLading, on_delete=models.CASCADE, related_name='line_items')
    product = models.ForeignKey(Product, on_delete=models.PROTECT)
    quantity = models.PositiveIntegerField()
    weight = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    description = models.TextField(blank=True)
    
    class Meta:
        verbose_name_plural = 'Bill of Lading Line Items'
    
    def __str__(self):
        return f"{self.product.name} x {self.quantity}"

    
class Order(models.Model):
    """Enhanced Order model with BOL integration"""
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('scheduled', 'Scheduled'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    product = models.ForeignKey(Product, on_delete=models.CASCADE, null=True)
    bill_of_lading = models.ForeignKey(BillOfLading, on_delete=models.SET_NULL, null=True, blank=True, related_name='orders')
    staff = models.ForeignKey(User, models.CASCADE, null=True)
    order_quantity = models.PositiveIntegerField(null=True)
    date = models.DateTimeField(auto_now_add=True)
    delivery_date = models.DateField(null=True, blank=True, help_text="Scheduled delivery date")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name_plural = 'Order'
        ordering = ['-date']

    def __str__(self):
        return f'{self.product} ordered by {self.staff.username if self.staff else "Unknown"}'
