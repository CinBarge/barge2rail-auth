"""
Custom admin forms for SSO user management.

Provides conditional form fields based on authentication type:
- Email/Password: Requires email and password
- Google OAuth: Requires email, no password
- Anonymous PIN: Requires PIN and display name, no email
"""

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.utils.safestring import mark_safe

from .models import User


class CustomUserCreationForm(UserCreationForm):
    """
    Custom user creation form with conditional fields based on auth_type.

    Handles three authentication types:
    1. Email/Password (auth_type='email')
    2. Google OAuth (auth_type='google')
    3. Anonymous PIN (auth_type='anonymous')
    """

    auth_type = forms.ChoiceField(
        choices=User.AUTH_TYPES,
        initial="email",
        widget=forms.RadioSelect,
        label="Authentication Type",
        help_text="",  # Will be set in __init__ with JavaScript
    )

    pin_code = forms.CharField(
        max_length=4,
        required=False,
        widget=forms.TextInput(attrs={"placeholder": "4-digit PIN"}),
        label="PIN Code",
        help_text="4-digit numeric PIN for anonymous users",
    )

    display_name = forms.CharField(
        max_length=100,
        required=False,
        label="Display Name",
        help_text="Name shown to other users (required for anonymous users)",
    )

    class Meta:
        model = User
        fields = (
            "auth_type",
            "email",
            "username",
            "display_name",
            "first_name",
            "last_name",
            "pin_code",
            "is_sso_admin",
            "is_staff",
            "is_active",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Make email not required by default (will validate in clean())
        self.fields["email"].required = False

        # Make password fields not required by default (will validate in clean())
        if "password1" in self.fields:
            self.fields["password1"].required = False
        if "password2" in self.fields:
            self.fields["password2"].required = False

        # Username is optional - if not provided, will be auto-generated
        if "username" in self.fields:
            self.fields["username"].required = False
            self.fields["username"].help_text = (
                "Optional. If blank, will be auto-generated. "
                "For anonymous users, this is their login ID."
            )

        # Add JavaScript for conditional field display
        js_code = mark_safe(  # nosec - static JavaScript, no user input
            """
<script>
function updateUserFormFields() {
    // Get selected auth type
    var authType = document.querySelector('input[name="auth_type"]:checked');
    if (!authType) return;
    var selectedType = authType.value;

    // Find field rows - Django admin uses .form-row with .field-{fieldname}
    var emailRow = document.querySelector('.field-email');
    var password1Row = document.querySelector('.field-password1');
    var password2Row = document.querySelector('.field-password2');
    var pinRow = document.querySelector('.field-pin_code');

    // Debug output
    console.log('Auth type selected:', selectedType);
    console.log('Found fields:', {
        email: !!emailRow,
        password1: !!password1Row,
        password2: !!password2Row,
        pin: !!pinRow
    });

    // Hide all conditional fields first
    if (emailRow) emailRow.style.display = 'none';
    if (password1Row) password1Row.style.display = 'none';
    if (password2Row) password2Row.style.display = 'none';
    if (pinRow) pinRow.style.display = 'none';

    // Show fields based on auth type
    if (selectedType === 'email') {
        // Email/Password: show email and passwords
        if (emailRow) emailRow.style.display = '';
        if (password1Row) password1Row.style.display = '';
        if (password2Row) password2Row.style.display = '';
    } else if (selectedType === 'google') {
        // Google OAuth: show email only
        if (emailRow) emailRow.style.display = '';
    } else if (selectedType === 'anonymous') {
        // Anonymous: show PIN only
        if (pinRow) pinRow.style.display = '';
    }
}

// Initialize on page load
(function() {
    console.log('User form script loaded');

    // Run immediately if DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            console.log('DOM loaded, setting up auth type listeners');
            updateUserFormFields();

            // Add change listeners
            var authInputs = document.querySelectorAll('input[name="auth_type"]');
            authInputs.forEach(function(input) {
                input.addEventListener('change', updateUserFormFields);
            });
        });
    } else {
        // DOM already loaded
        console.log('DOM already ready, running immediately');
        updateUserFormFields();

        var authInputs = document.querySelectorAll('input[name="auth_type"]');
        authInputs.forEach(function(input) {
            input.addEventListener('change', updateUserFormFields);
        });
    }
})();
</script>
        """
        )

        # Set auth_type help_text with JavaScript
        help_text = "Select how this user will authenticate. "
        help_text += "Fields will show/hide based on your selection."
        self.fields["auth_type"].help_text = mark_safe(  # nosec B308, B703
            help_text + str(js_code)
        )

    def clean(self):
        """Validate form data based on selected auth_type."""
        cleaned_data = super().clean()
        auth_type = cleaned_data.get("auth_type")

        # Validation for Email/Password users
        if auth_type == "email":
            if not cleaned_data.get("email"):
                raise ValidationError(
                    {"email": "Email is required for Email/Password authentication"}
                )

            # Password validation (only if passwords are present in form)
            if "password1" in self.fields:
                password1 = cleaned_data.get("password1")
                password2 = cleaned_data.get("password2")

                if not password1 or not password2:
                    raise ValidationError(  # pragma: allowlist secret
                        {
                            "password1": (
                                "Password is required for "
                                "Email/Password authentication"
                            )
                        }
                    )

                if password1 != password2:
                    raise ValidationError({"password2": "Passwords don't match"})

        # Validation for Google OAuth users
        elif auth_type == "google":
            if not cleaned_data.get("email"):
                raise ValidationError(
                    {"email": "Email is required for Google OAuth authentication"}
                )
            # No password required for Google OAuth

        # Validation for Anonymous PIN users
        elif auth_type == "anonymous":
            pin_code = cleaned_data.get("pin_code")
            display_name = cleaned_data.get("display_name")

            if not pin_code:
                raise ValidationError(
                    {"pin_code": "PIN is required for Anonymous authentication"}
                )

            if len(pin_code) != 4 or not pin_code.isdigit():
                raise ValidationError({"pin_code": "PIN must be exactly 4 digits"})

            if not display_name:
                raise ValidationError(
                    {"display_name": "Display name is required for Anonymous users"}
                )

            # Set is_anonymous flag
            cleaned_data["is_anonymous"] = True

        return cleaned_data

    def save(self, commit=True):
        """Save user with auth_type-specific logic."""
        user = super().save(commit=False)

        auth_type = self.cleaned_data.get("auth_type")

        # Set auth_type and related flags
        user.auth_type = auth_type

        if auth_type == "email":
            user.auth_method = "password"
            user.is_anonymous = False

        elif auth_type == "google":
            user.auth_method = "google"
            user.is_anonymous = False
            # Google OAuth users don't need password
            user.set_unusable_password()

        elif auth_type == "anonymous":
            user.auth_method = "password"  # Will use PIN for auth
            user.is_anonymous = True
            user.pin_code = self.cleaned_data.get("pin_code")
            user.display_name = self.cleaned_data.get("display_name")
            user.set_unusable_password()  # Anonymous users use PIN, not password

        # Username will be auto-generated in model's save() method

        if commit:
            user.save()

        return user

    # Note: No Media class needed - JavaScript injected via help_text in __init__
