from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Application, UserRole, RefreshToken


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'username', 'first_name', 'last_name', 'is_sso_admin', 'is_active', 'created_at']
    list_filter = ['is_sso_admin', 'is_active', 'is_staff', 'created_at']
    search_fields = ['email', 'username', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('SSO Info', {'fields': ('is_sso_admin', 'phone')}),
    )
    
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('SSO Info', {'fields': ('email', 'is_sso_admin', 'phone')}),
    )


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['name', 'client_id', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'client_id']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        (None, {
            'fields': ('name', 'description', 'is_active')
        }),
        ('OAuth Settings', {
            'fields': ('client_id', 'client_secret', 'redirect_uris')
        }),
        ('Metadata', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = ['user', 'application', 'role', 'created_at']
    list_filter = ['role', 'application', 'created_at']
    search_fields = ['user__email', 'user__username', 'application__name']
    raw_id_fields = ['user', 'application']
    readonly_fields = ['id', 'created_at', 'updated_at']


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'application', 'expires_at', 'created_at']
    list_filter = ['application', 'expires_at', 'created_at']
    search_fields = ['user__email', 'user__username']
    raw_id_fields = ['user', 'application']
    readonly_fields = ['id', 'token', 'created_at']
