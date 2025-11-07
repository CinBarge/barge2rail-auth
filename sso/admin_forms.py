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
        help_text="Select how this user will authenticate",
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

        # Username will be auto-generated, so hide it from form
        if "username" in self.fields:
            self.fields["username"].required = False
            self.fields["username"].widget = forms.HiddenInput()

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

    # Media class removed - JavaScript is injected inline in UserAdmin instead
