from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, Application, UserRole, ApplicationRole, RefreshToken


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    list_display = ['email', 'display_name', 'auth_type', 'is_sso_admin', 'is_active', 'created_at']
    list_filter = ['auth_type', 'is_sso_admin', 'is_active', 'is_anonymous', 'created_at']
    search_fields = ['email', 'display_name', 'username', 'anonymous_username']
    readonly_fields = ['id', 'google_id', 'anonymous_username', 'pin_code', 'created_at', 'updated_at']
    ordering = ['-created_at']

    fieldsets = (
        ('User Information', {
            'fields': ('email', 'username', 'display_name', 'phone')
        }),
        ('Authentication', {
            'fields': ('auth_type', 'google_id', 'is_anonymous', 'anonymous_username', 'pin_code')
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'is_sso_admin', 'groups', 'user_permissions')
        }),
        ('Personal info', {
            'fields': ('first_name', 'last_name', 'date_joined', 'last_login')
        }),
        ('Metadata', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'display_name', 'auth_type', 'is_sso_admin'),
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related()

    def get_search_results(self, request, queryset, search_term):
        # Enable autocomplete for UserRole and ApplicationRole admin
        queryset, use_distinct = super().get_search_results(request, queryset, search_term)
        return queryset, use_distinct

    def has_delete_permission(self, request, obj=None):
        # Prevent deletion of admin users
        if obj and obj.is_sso_admin:
            return False
        return super().has_delete_permission(request, obj)


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug', 'client_id', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['name', 'slug', 'client_id']
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
    list_display = ['user_email', 'user_display_name', 'application', 'role', 'created_at']
    list_filter = ['role', 'application', 'created_at']
    search_fields = ['user__email', 'user__display_name', 'user__username', 'application__name']
    autocomplete_fields = ['user', 'application']
    readonly_fields = ['id', 'created_at', 'updated_at']

    def user_email(self, obj):
        return obj.user.email or obj.user.anonymous_username
    user_email.short_description = 'User Email'
    user_email.admin_order_field = 'user__email'

    def user_display_name(self, obj):
        return obj.user.display_name or obj.user.display_identifier
    user_display_name.short_description = 'Display Name'
    user_display_name.admin_order_field = 'user__display_name'

    fieldsets = (
        ('Role Assignment', {
            'fields': ('user', 'application', 'role')
        }),
        ('Permissions', {
            'fields': ('permissions',),
            'description': 'JSON field for custom permissions per role'
        }),
        ('Metadata', {
            'fields': ('id', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(ApplicationRole)
class ApplicationRoleAdmin(admin.ModelAdmin):
    list_display = ['user', 'application', 'role', 'assigned_date']
    list_filter = ['application', 'role', 'assigned_date']
    search_fields = ['user__email', 'user__display_name', 'user__username', 'user__anonymous_username']
    autocomplete_fields = ['user']
    
    fieldsets = (
        ('Role Assignment', {
            'fields': ('user', 'application', 'role')
        }),
        ('Additional Details', {
            'fields': ('permissions', 'notes'),
            'classes': ('collapse',)
        }),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('user')


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ['user', 'application', 'expires_at', 'created_at']
    list_filter = ['application', 'expires_at', 'created_at']
    search_fields = ['user__email', 'user__username']
    raw_id_fields = ['user', 'application']
    readonly_fields = ['id', 'token', 'created_at']
