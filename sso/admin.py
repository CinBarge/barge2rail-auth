from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html

from .admin_forms import CustomUserCreationForm
from .models import (
    Application,
    ApplicationRole,
    AuthorizationCode,
    RefreshToken,
    User,
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
        "email",
        "display_name",
        "auth_type",
        "is_sso_admin",
        "is_active",
        "created_at",
    ]
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

    class Media:
        js = ("admin/js/user_creation_form.js",)
        css = {"all": ("admin/css/user_creation_form.css",)}

    def get_form(self, request, obj=None, **kwargs):
        """Override to inject JavaScript for conditional field display."""
        form = super().get_form(request, obj, **kwargs)

        # Add help text with JavaScript for conditional fields (only on add page)
        if obj is None:  # Adding new user
            # The JavaScript will be added via Media class above
            pass

        return form

    def render_change_form(
        self, request, context, add=False, change=False, form_url="", obj=None
    ):
        """Add custom JavaScript for conditional field display on add form."""
        response = super().render_change_form(
            request, context, add, change, form_url, obj
        )

        if add:  # Only on user creation form
            # Inject inline JavaScript for immediate field toggling
            extra_js = format_html(
                """
<script type="text/javascript">
(function() {{
    if (typeof django === 'undefined' || !django.jQuery) {{
        return;  // Wait for Django's jQuery to load
    }}

    django.jQuery(document).ready(function($) {{
        // Field containers
        var authTypeField = $('.field-auth_type');
        var emailField = $('.field-email');
        var displayNameField = $('.field-display_name');
        var password1Field = $('.field-password1');
        var password2Field = $('.field-password2');
        var pinField = $('.field-pin_code');
        var firstNameField = $('.field-first_name');
        var lastNameField = $('.field-last_name');

        function updateFieldVisibility() {{
            var selectedType = $('input[name="auth_type"]:checked').val();

            // Hide all conditional fields first
            emailField.hide();
            password1Field.hide();
            password2Field.hide();
            pinField.hide();

            if (selectedType === 'email') {{
                // Email/Password: show email, password fields
                emailField.show();
                password1Field.show();
                password2Field.show();
                displayNameField.show();
                firstNameField.show();
                lastNameField.show();

            }} else if (selectedType === 'google') {{
                // Google OAuth: show email only, hide passwords
                emailField.show();
                displayNameField.show();
                firstNameField.show();
                lastNameField.show();

            }} else if (selectedType === 'anonymous') {{
                // Anonymous PIN: show PIN and display name, hide email
                pinField.show();
                displayNameField.show();
                firstNameField.show();
                lastNameField.show();
            }}
        }}

        // Initial update
        updateFieldVisibility();

        // Update on auth_type change
        $('input[name="auth_type"]').on('change', updateFieldVisibility);
    }});
}})();
</script>
            """
            )

            # Add the JavaScript to the response content
            if hasattr(response, "content"):
                response.content = (
                    response.content.decode("utf-8")
                    if isinstance(response.content, bytes)
                    else response.content
                )
                response.content = response.content.replace(
                    "</body>", str(extra_js) + "</body>"
                )
                if isinstance(response.content, str):
                    response.content = response.content.encode("utf-8")

        return response

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


@admin.register(ApplicationRole)
class ApplicationRoleAdmin(admin.ModelAdmin):
    list_display = ["user", "application", "role", "assigned_date"]
    list_filter = ["application", "role", "assigned_date"]
    search_fields = [
        "user__email",
        "user__display_name",
        "user__username",
        "user__anonymous_username",
    ]
    autocomplete_fields = ["user"]

    fieldsets = (
        ("Role Assignment", {"fields": ("user", "application", "role")}),
        (
            "Additional Details",
            {"fields": ("permissions", "notes"), "classes": ("collapse",)},
        ),
    )

    def get_queryset(self, request):
        return super().get_queryset(request).select_related("user")


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
