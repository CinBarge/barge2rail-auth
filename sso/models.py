from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid
import random
import string


class User(AbstractUser):
    AUTH_TYPES = [
        ('email', 'Email/Password'),
        ('google', 'Google Sign-In'),
        ('anonymous', 'Anonymous PIN'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, null=True, blank=True)  # Allow null for anonymous
    phone = models.CharField(max_length=20, blank=True)
    display_name = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    is_sso_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # New fields for enhanced auth
    auth_type = models.CharField(max_length=20, choices=AUTH_TYPES, default='email')
    google_id = models.CharField(max_length=255, blank=True, null=True, unique=True)
    
    # Anonymous user fields
    anonymous_username = models.CharField(max_length=50, blank=True, null=True, unique=True)
    pin_code = models.CharField(max_length=6, blank=True, null=True)
    is_anonymous = models.BooleanField(default=False)
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []  # Remove required fields to allow anonymous users
    
    class Meta:
        db_table = 'sso_users'
        ordering = ['-created_at']
    
    def save(self, *args, **kwargs):
        # Auto-generate anonymous username if needed
        if self.is_anonymous and not self.anonymous_username:
            self.anonymous_username = self.generate_anonymous_username()
        
        # Auto-generate PIN if needed
        if self.is_anonymous and not self.pin_code:
            self.pin_code = self.generate_pin()
        
        # Set username for anonymous users
        if self.is_anonymous and not self.username:
            self.username = self.anonymous_username
            
        super().save(*args, **kwargs)
    
    def generate_anonymous_username(self):
        """Generate unique anonymous username like 'Guest-ABC123'"""
        while True:
            suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            username = f"Guest-{suffix}"
            if not User.objects.filter(anonymous_username=username).exists():
                return username
    
    def generate_pin(self):
        """Generate 6-digit PIN code"""
        return ''.join(random.choices(string.digits, k=6))
    
    @property
    def display_identifier(self):
        """Return appropriate identifier for display"""
        if self.is_anonymous:
            return self.anonymous_username
        return self.email or self.username


class Application(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=50, unique=True, default='')
    client_id = models.CharField(max_length=100, unique=True)
    client_secret = models.CharField(max_length=255)
    redirect_uris = models.TextField(help_text="Comma-separated list of allowed redirect URIs")
    is_active = models.BooleanField(default=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.name
    
    class Meta:
        db_table = 'sso_applications'
        ordering = ['name']


class UserRole(models.Model):
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('manager', 'Manager'),
        ('user', 'User'),
        ('viewer', 'Viewer'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='roles')
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='user_roles')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    permissions = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'sso_user_roles'
        unique_together = ['user', 'application']
        ordering = ['application', 'user']


class ApplicationRole(models.Model):
    """User roles for different business applications"""
    APPLICATION_CHOICES = [
        ('primetrade', 'PrimeTrade'),
        ('database', 'Customer Database'),
        ('repair', 'Repair Ticketing'),
        ('barge', 'Barge Tracking'),
        ('admin', 'Admin Dashboard'),
    ]
    
    ROLE_CHOICES = [
        ('admin', 'Administrator'),
        ('user', 'Standard User'),
        ('viewer', 'Read Only'),
        ('operator', 'Operator'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='application_roles')
    application = models.CharField(max_length=50, choices=APPLICATION_CHOICES)
    role = models.CharField(max_length=50, choices=ROLE_CHOICES)
    permissions = models.JSONField(default=list, blank=True)
    assigned_date = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)
    
    class Meta:
        unique_together = ['user', 'application']
        verbose_name = 'Application Role'
        verbose_name_plural = 'Application Roles'
        db_table = 'sso_application_roles'
    
    def __str__(self):
        return f"{self.user.email or self.user.anonymous_username} - {self.get_application_display()}: {self.get_role_display()}"


class RefreshToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='refresh_tokens')
    application = models.ForeignKey(Application, on_delete=models.CASCADE, related_name='refresh_tokens')
    token = models.TextField(unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'sso_refresh_tokens'
        ordering = ['-created_at']
