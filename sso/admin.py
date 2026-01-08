from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .admin_forms import CustomUserCreationForm
from .models import (
    Application,
    ApplicationRole,
    AuthorizationCode,
    Feature,
    Permission,
    RefreshToken,
    Role,
    RoleFeaturePermission,
    Tenant,
    User,
    UserAppRole,
    UserRole,
)

# Unregister oauth2_provider's Application admin if it was registered
try:
    admin.site.unregister(Application)
except admin.sites.NotRegistered:
    pass


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    # Use custom form for user creation
    add_form = CustomUserCreationForm

    list_display = [
        "user_identifier",
        "display_name",
        "auth_type",
        "is_sso_admin",
        "is_active",
        "created_at",
    ]

    @admin.display(description="User", ordering="username")
    def user_identifier(self, obj):
        """Show email, username, or anonymous_username - whichever is available"""
        return obj.email or obj.username or obj.anonymous_username or f"User {obj.id}"

    list_filter = [
        "auth_type",
        "is_sso_admin",
        "is_active",
        "is_anonymous",
        "created_at",
    ]
    search_fields = ["email", "display_name", "username", "anonymous_username"]
    readonly_fields = [
        "id",
        "google_id",
        "anonymous_username",
        "created_at",
        "updated_at",
    ]
    ordering = ["-created_at"]

    fieldsets = (
        (
            "User Information",
            {"fields": ("email", "username", "display_name", "phone")},
        ),
        (
            "Authentication",
            {
                "fields": (
                    "auth_type",
                    "google_id",
                    "is_anonymous",
                    "anonymous_username",
                    "pin_code",
                    "force_pin_change",
                )
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "is_sso_admin",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "Personal info",
            {"fields": ("first_name", "last_name", "date_joined", "last_login")},
        ),
        (
            "Metadata",
            {"fields": ("id", "created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    add_fieldsets = (
        (
            "Authentication Type",
            {
                "classes": ("wide",),
                "fields": ("auth_type",),
                "description": (
                    "Select the authentication method for this user. "
                    "This determines which fields are required below."
                ),
            },
        ),
        (
            "User Details",
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "email",
                    "display_name",
                    "first_name",
                    "last_name",
                    "password1",
                    "password2",
                    "pin_code",
                ),
            },
        ),
        (
            "Permissions",
            {
                "classes": ("wide",),
                "fields": (
                    "is_sso_admin",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )

    # Note: Dynamic field show/hide handled by JavaScript in CustomUserCreationForm
    # Form validation in clean() ensures correct fields are filled

    def get_queryset(self, request):
        return super().get_queryset(request).select_related()

    def get_search_results(self, request, queryset, search_term):
        # Enable autocomplete for UserRole and ApplicationRole admin
        queryset, use_distinct = super().get_search_results(
            request, queryset, search_term
        )
        return queryset, use_distinct

    def has_delete_permission(self, request, obj=None):
        # Prevent deletion of admin users
        if obj and obj.is_sso_admin:
            return False
        return super().has_delete_permission(request, obj)


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = ["name", "slug", "client_id", "client_type", "is_active", "created"]
    list_filter = ["is_active", "client_type", "authorization_grant_type", "created"]
    search_fields = ["name", "slug", "client_id"]
    readonly_fields = ["id", "created", "updated"]

    fieldsets = (
        (None, {"fields": ("name", "slug", "description", "is_active", "user")}),
        (
            "OAuth2 Settings",
            {
                "fields": (
                    "client_id",
                    "client_secret",
                    "client_type",
                    "authorization_grant_type",
                    "redirect_uris",
                    "skip_authorization",
                )
            },
        ),
        (
            "Metadata",
            {"fields": ("id", "created", "updated"), "classes": ("collapse",)},
        ),
    )


@admin.register(UserRole)
class UserRoleAdmin(admin.ModelAdmin):
    list_display = [
        "user_email",
        "user_display_name",
        "application",
        "role",
        "created_at",
    ]
    list_filter = ["role", "application", "created_at"]
    search_fields = [
        "user__email",
        "user__display_name",
        "user__username",
        "application__name",
    ]
    autocomplete_fields = ["user", "application"]
    readonly_fields = ["id", "created_at", "updated_at"]

    @admin.display(
        description="User Email",
        ordering="user__email",
    )
    def user_email(self, obj):
        return obj.user.email or obj.user.anonymous_username

    @admin.display(
        description="Display Name",
        ordering="user__display_name",
    )
    def user_display_name(self, obj):
        return obj.user.display_name or obj.user.display_identifier

    fieldsets = (
        ("Role Assignment", {"fields": ("user", "application", "role")}),
        (
            "Permissions",
            {
                "fields": ("permissions",),
                "description": "JSON field for custom permissions per role",
            },
        ),
        (
            "Metadata",
            {"fields": ("id", "created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


# =============================================================================
# DEPRECATED: ApplicationRole is replaced by UserAppRole (RBAC system)
# Run `python manage.py migrate_roles` to migrate legacy entries.
# This admin section kept for viewing/auditing existing legacy data.
# Do not create new entries here - use UserAppRole instead.
# Safe to remove after Jan 2026 once all legacy data migrated.
# =============================================================================
@admin.register(ApplicationRole)
class ApplicationRoleAdmin(admin.ModelAdmin):
    """
    DEPRECATED: Use UserAppRole (RBAC) instead.

    This admin is kept for viewing/auditing legacy ApplicationRole entries.
    Run `python manage.py migrate_roles` to migrate to UserAppRole.
    """

    list_display = ["user", "application", "role", "assigned_date", "migration_status"]
    list_filter = ["application", "role", "assigned_date"]
    search_fields = [
        "user__email",
        "user__display_name",
        "user__username",
        "user__anonymous_username",
    ]
    autocomplete_fields = ["user"]

    fieldsets = (
        (
            "⚠️ DEPRECATED - Use UserAppRole Instead",
            {
                "fields": ("user", "application", "role"),
                "description": (
                    "This system is deprecated. "
                    "Use RBAC > User App Roles for new assignments. "
                    "Run 'python manage.py migrate_roles' to migrate."
                ),
            },
        ),
        (
            "Additional Details",
            {"fields": ("permissions", "notes"), "classes": ("collapse",)},
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user", "application")

    @admin.display(description="Migrated?")
    def migration_status(self, obj):
        """Check if this legacy role has been migrated to UserAppRole."""
        from .models import Role, UserAppRole

        # Find matching RBAC role
        try:
            rbac_role = Role.objects.get(
                application=obj.application,
                legacy_role__iexact=obj.role,
                is_active=True,
            )
            # Check if UserAppRole exists
            if UserAppRole.objects.filter(user=obj.user, role=rbac_role).exists():
                return "✅ Yes"
        except Role.DoesNotExist:
            return "⚠️ No RBAC role"
        except Role.MultipleObjectsReturned:
            return "⚠️ Multiple roles"
        return "❌ No"

    def has_add_permission(self, request):
        """Prevent creating new legacy ApplicationRole entries."""
        return False


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = ["user", "application", "expires_at", "created_at"]
    list_filter = ["application", "expires_at", "created_at"]
    search_fields = ["user__email", "user__username"]
    raw_id_fields = ["user", "application"]
    readonly_fields = ["id", "token", "created_at"]


@admin.register(AuthorizationCode)
class AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = [
        "code_preview",
        "user_email",
        "application",
        "used",
        "expires_at",
        "created_at",
    ]
    list_filter = ["used", "application", "created_at"]
    search_fields = ["code", "user__email", "application__name"]
    readonly_fields = ["code", "created_at", "expires_at"]
    autocomplete_fields = ["user", "application"]

    @admin.display(description="Code")
    def code_preview(self, obj):
        return f"{obj.code[:20]}..."

    @admin.display(
        description="User",
        ordering="user__email",
    )
    def user_email(self, obj):
        return obj.user.email or obj.user.anonymous_username

    fieldsets = (
        ("Authorization Code", {"fields": ("code", "used", "expires_at")}),
        (
            "OAuth Details",
            {"fields": ("user", "application", "redirect_uri", "scope", "state")},
        ),
        ("Metadata", {"fields": ("created_at",), "classes": ("collapse",)}),
    )


# =============================================================================
# Phase 5: RBAC Admin Classes (December 2025)
# =============================================================================


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    """Admin for managing tenant codes available in role assignment dropdowns."""

    list_display = ["code", "name", "is_active", "created_at"]
    list_filter = ["is_active"]
    search_fields = ["code", "name"]
    ordering = ["code"]

    fieldsets = ((None, {"fields": ("code", "name", "is_active")}),)


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    """Admin for base permission types (view, create, modify, delete, etc.)."""

    list_display = ["code", "name", "description", "display_order"]
    list_editable = ["display_order"]
    search_fields = ["code", "name"]
    ordering = ["display_order", "code"]


@admin.register(Feature)
class FeatureAdmin(admin.ModelAdmin):
    """Admin for application features."""

    list_display = ["code", "name", "application", "is_active", "display_order"]
    list_filter = ["application", "is_active"]
    list_editable = ["is_active", "display_order"]
    search_fields = ["code", "name", "application__name"]
    autocomplete_fields = ["application"]
    ordering = ["application", "display_order", "code"]

    fieldsets = (
        (None, {"fields": ("application", "code", "name", "description")}),
        ("Status", {"fields": ("is_active", "display_order")}),
    )


class RoleFeaturePermissionInline(admin.TabularInline):
    """Inline for assigning feature permissions to a role."""

    model = RoleFeaturePermission
    extra = 1
    autocomplete_fields = ["feature", "permission"]

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related("feature", "permission")


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """Admin for application roles with permission matrix link."""

    list_display = [
        "name",
        "application",
        "code",
        "legacy_role",
        "is_active",
        "permission_count",
        "edit_permissions_link",
    ]
    list_filter = ["application", "is_active", "legacy_role"]
    search_fields = ["code", "name", "application__name"]
    autocomplete_fields = ["application"]
    readonly_fields = ["created_at", "updated_at", "permission_matrix_link"]

    @admin.display(description="Permissions")
    def permission_count(self, obj):
        count = obj.feature_permissions.count()
        return f"{count} permission(s)"

    @admin.display(description="Edit Permissions")
    def edit_permissions_link(self, obj):
        from django.utils.html import format_html

        url = f"/admin/sso/role/{obj.pk}/permissions/"
        return format_html('<a href="{}">Edit Permissions</a>', url)

    @admin.display(description="Permission Matrix")
    def permission_matrix_link(self, obj):
        from django.utils.html import format_html

        url = f"/admin/sso/role/{obj.pk}/permissions/"
        return format_html(
            '<a href="{}" class="button" style="padding: 10px 15px;">'
            "Open Permission Matrix Editor</a>",
            url,
        )

    fieldsets = (
        (None, {"fields": ("application", "code", "name", "description")}),
        (
            "Permissions",
            {
                "fields": ("permission_matrix_link",),
                "description": (
                    "Use the Permission Matrix to edit feature "
                    "permissions for this role."
                ),
            },
        ),
        (
            "Backward Compatibility",
            {
                "fields": ("legacy_role",),
                "description": (
                    "Map to legacy role for apps not yet migrated to new RBAC"
                ),
            },
        ),
        ("Status", {"fields": ("is_active",)}),
        (
            "Metadata",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )


@admin.register(RoleFeaturePermission)
class RoleFeaturePermissionAdmin(admin.ModelAdmin):
    """Admin for individual role-feature-permission mappings."""

    list_display = ["role", "feature", "permission"]
    list_filter = ["role__application", "role", "feature", "permission"]
    search_fields = [
        "role__name",
        "role__code",
        "feature__name",
        "feature__code",
        "permission__name",
    ]
    autocomplete_fields = ["role", "feature", "permission"]

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("role", "role__application", "feature", "permission")
        )


@admin.register(UserAppRole)
class UserAppRoleAdmin(admin.ModelAdmin):
    """Admin for assigning users to roles."""

    list_display = [
        "user_identifier",
        "role",
        "application_name",
        "tenant_code",
        "is_active",
        "assigned_at",
    ]
    list_filter = ["role__application", "role", "is_active", "tenant_code"]
    search_fields = [
        "user__email",
        "user__display_name",
        "user__username",
        "user__anonymous_username",
        "role__name",
        "tenant_code",
    ]
    autocomplete_fields = ["user", "role", "assigned_by"]
    readonly_fields = ["assigned_at", "updated_at"]
    raw_id_fields = ["assigned_by"]

    @admin.display(description="User", ordering="user__email")
    def user_identifier(self, obj):
        return obj.user.email or obj.user.anonymous_username or str(obj.user)

    @admin.display(description="Application", ordering="role__application__name")
    def application_name(self, obj):
        return obj.role.application.name

    fieldsets = (
        ("Assignment", {"fields": ("user", "role", "tenant_code")}),
        ("Status", {"fields": ("is_active",)}),
        (
            "Audit",
            {
                "fields": ("assigned_by", "notes", "assigned_at", "updated_at"),
                "classes": ("collapse",),
            },
        ),
    )

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("user", "role", "role__application", "assigned_by")
        )
