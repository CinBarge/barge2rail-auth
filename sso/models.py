import secrets
import string
import uuid
from datetime import timedelta

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from oauth2_provider.models import AbstractApplication


class UserManager(BaseUserManager):
    """Custom user manager that doesn't require username."""

    def create_user(self, email=None, password=None, **extra_fields):
        """Create and save a regular user with email (username auto-generated)."""
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)

        # Don't require username - it will be auto-generated in save()
        user = self.model(email=email, **extra_fields)

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)
        return user

    def create_superuser(self, email=None, password=None, **extra_fields):
        """Create and save a superuser."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_sso_admin", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    AUTH_TYPES = [
        ("email", "Email/Password"),
        ("google", "Google Sign-In"),
        ("anonymous", "Anonymous PIN"),
    ]

    AUTH_METHODS = [
        ("google", "Google OAuth"),
        ("password", "Password Authentication"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(
        unique=True, null=True, blank=True
    )  # Allow null for anonymous
    phone = models.CharField(max_length=20, blank=True)
    display_name = models.CharField(max_length=100, blank=True)
    is_active = models.BooleanField(default=True)
    is_sso_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # New fields for enhanced auth
    auth_type = models.CharField(max_length=20, choices=AUTH_TYPES, default="email")
    auth_method = models.CharField(
        max_length=20,
        choices=AUTH_METHODS,
        default="password",
        help_text="How this user authenticates",
    )
    google_id = models.CharField(max_length=255, blank=True, null=True, unique=True)

    # Anonymous user fields
    anonymous_username = models.CharField(
        max_length=50, blank=True, null=True, unique=True
    )
    # PIN is stored as a hash (like password) - use set_pin()/check_pin() methods
    pin_code = models.CharField(max_length=128, blank=True, null=True)
    is_anonymous = models.BooleanField(default=False)

    # Use custom manager
    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []  # Remove required fields to allow anonymous users

    class Meta:
        db_table = "sso_users"
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        # Auto-generate username based on auth_type if not set
        if not self.username:
            if self.auth_type in ["email", "google"] and self.email:
                # For email/password and Google OAuth: username = email
                self.username = self.email
            elif self.auth_type == "anonymous" or self.is_anonymous:
                # For anonymous users: generate unique username
                if not self.anonymous_username:
                    self.anonymous_username = self.generate_anonymous_username()
                self.username = self.anonymous_username
            else:
                # Fallback: generate UUID-based username
                self.username = f"user_{uuid.uuid4().hex[:8]}"

        # Auto-generate anonymous username if needed for anonymous users
        if (
            self.auth_type == "anonymous" or self.is_anonymous
        ) and not self.anonymous_username:
            self.anonymous_username = self.generate_anonymous_username()

        # Auto-generate and hash PIN if needed for anonymous users
        # Note: PIN is hashed on save, so we track if we need to generate one
        if (self.auth_type == "anonymous" or self.is_anonymous) and not self.pin_code:
            # Generate PIN and hash it - plaintext returned via _plaintext_pin
            plaintext_pin = self.generate_pin()
            self._plaintext_pin = plaintext_pin  # Store for returning to user
            self.pin_code = make_password(plaintext_pin)

        super().save(*args, **kwargs)

    def generate_anonymous_username(self):
        """Generate unique anonymous username like 'Guest-ABC123'

        Uses cryptographically secure random for username generation.
        """
        charset = string.ascii_uppercase + string.digits
        while True:
            # Use secrets.choice for cryptographically secure random selection
            suffix = "".join(secrets.choice(charset) for _ in range(6))
            username = f"Guest-{suffix}"
            if not User.objects.filter(anonymous_username=username).exists():
                return username

    def generate_pin(self):
        """Generate 12-digit numeric PIN for anonymous users.

        Uses secrets.randbelow() for cryptographically secure generation.
        Returns plaintext PIN (caller responsible for hashing if storing).
        """
        return "".join(str(secrets.randbelow(10)) for _ in range(12))

    def set_pin(self, plaintext_pin):
        """Hash and store a PIN (like set_password for passwords).

        Args:
            plaintext_pin: 12-digit numeric PIN string
        """
        if not plaintext_pin or len(plaintext_pin) != 12 or not plaintext_pin.isdigit():
            from django.core.exceptions import ValidationError

            raise ValidationError("PIN must be exactly 12 digits")
        self.pin_code = make_password(plaintext_pin)

    def check_pin(self, plaintext_pin):
        """Verify a PIN against the stored hash (like check_password).

        Args:
            plaintext_pin: PIN to verify

        Returns:
            bool: True if PIN matches, False otherwise
        """
        if not self.pin_code:
            return False
        return check_password(plaintext_pin, self.pin_code)

    @property
    def display_identifier(self):
        """Return appropriate identifier for display"""
        if self.is_anonymous:
            return self.anonymous_username
        return self.email or self.username

    def requires_google_oauth(self):
        """Check if user must use Google OAuth (barge2rail.com users)"""
        return self.email and self.email.endswith("@barge2rail.com")


class Application(AbstractApplication):
    """OAuth2 Application model compatible with django-oauth-toolkit.

    Extends AbstractApplication with custom fields for B2R SSO.
    Maintains backward compatibility with existing applications.
    """

    # Override id to use UUID (AbstractApplication uses BigAutoField by default)
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Custom fields (in addition to AbstractApplication fields)
    slug = models.SlugField(max_length=50, unique=True, default="")
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)

    # Override AbstractApplication fields to match existing schema
    name = models.CharField(max_length=100, unique=True)
    client_id = models.CharField(
        max_length=100,
        unique=True,
        db_index=True,
        blank=True,
        help_text="Auto-generated if left blank. Format: app_XXXXXXXXXXXXXXXX",
    )
    client_secret = models.CharField(
        max_length=255,
        blank=True,
        help_text=(
            "Auto-generated if left blank. Cryptographically secure " "random string."
        ),
    )

    # AbstractApplication required fields with sensible defaults
    client_type = models.CharField(
        max_length=32,
        choices=AbstractApplication.CLIENT_TYPES,
        default=AbstractApplication.CLIENT_CONFIDENTIAL,
        help_text="Confidential clients can keep secrets, public clients cannot",
    )
    authorization_grant_type = models.CharField(
        max_length=32,
        choices=AbstractApplication.GRANT_TYPES,
        default=AbstractApplication.GRANT_AUTHORIZATION_CODE,
        help_text="OAuth2 grant type for this application",
    )
    redirect_uris = models.TextField(
        blank=True, help_text="Comma or newline-separated list of allowed redirect URIs"
    )
    skip_authorization = models.BooleanField(
        default=False, help_text="Skip authorization screen for trusted applications"
    )

    # Override algorithm field to default to RS256 for OIDC support
    algorithm = models.CharField(
        max_length=5,
        choices=AbstractApplication.ALGORITHM_TYPES,
        default=AbstractApplication.RS256_ALGORITHM,
        blank=True,
        help_text="RS256 uses global OIDC_RSA_PRIVATE_KEY for signing ID tokens",
    )

    # Optional: Link application to creating user (nullable for backward compatibility)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="oauth_applications",
        help_text="User who created this application (optional)",
    )

    # Note: AbstractApplication provides 'created' and 'updated' timestamp fields

    def save(self, *args, **kwargs):
        # Auto-generate client_id if not provided
        if not self.client_id:
            self.client_id = self.generate_client_id()

        # Auto-generate client_secret if not provided
        if not self.client_secret:
            self.client_secret = self.generate_client_secret()

        super().save(*args, **kwargs)

    def generate_client_id(self):
        """Generate unique client_id like 'app_1a2b3c4d5e6f7g8h'"""
        while True:
            # Generate 16 character random string (hex)
            random_part = secrets.token_hex(8)  # 8 bytes = 16 hex chars
            client_id = f"app_{random_part}"
            if not Application.objects.filter(client_id=client_id).exists():
                return client_id

    def generate_client_secret(self):
        """Generate cryptographically secure client secret (64 characters)"""
        return secrets.token_urlsafe(48)  # 48 bytes = 64 URL-safe characters

    def __str__(self):
        return self.name

    class Meta:
        db_table = "sso_applications"
        ordering = ["name"]


class AuthorizationCode(models.Model):
    """Temporary authorization codes for OAuth 2.0 authorization code flow"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=128, unique=True, db_index=True)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="authorization_codes"
    )
    application = models.ForeignKey(
        Application, on_delete=models.CASCADE, related_name="authorization_codes"
    )
    redirect_uri = models.URLField()
    scope = models.CharField(max_length=255, default="openid email profile")
    state = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        db_table = "sso_authorization_codes"
        indexes = [
            models.Index(fields=["code", "used"]),
        ]
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.code:
            self.code = secrets.token_urlsafe(32)
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
        super().save(*args, **kwargs)

    def is_valid(self):
        """Check if code is still valid (not expired and not used)"""
        return not self.used and timezone.now() < self.expires_at

    def __str__(self):
        return f"{self.code[:10]}... for {self.application.name}"


class UserRole(models.Model):
    ROLE_CHOICES = [
        ("admin", "Administrator"),
        ("manager", "Manager"),
        ("user", "User"),
        ("viewer", "Viewer"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="roles")
    application = models.ForeignKey(
        Application, on_delete=models.CASCADE, related_name="user_roles"
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    permissions = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "sso_user_roles"
        unique_together = ["user", "application"]
        ordering = ["application", "user"]


class ApplicationRole(models.Model):
    """
    User roles for different business applications.

    Three-role system with automatic permission assignment:
    - Admin: Full access to everything (full_access)
    - Office: Daily operations (read, write, delete)
    - Client: View-only access (read)

    Permissions are automatically assigned based on role selection.
    Manual override is possible by setting permissions before save.

    Note: application field is now a ForeignKey to Application model.
    Applications are managed through the Application model, not hardcoded choices.
    """

    ROLE_CHOICES = [
        ("Admin", "Admin"),
        ("Office", "Office"),
        ("Client", "Client"),
    ]

    # Automatic permission mapping for each role
    ROLE_PERMISSIONS = {
        "Admin": ["full_access"],
        "Office": ["read", "write", "delete"],
        "Client": ["read"],
    }

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="application_roles"
    )
    application = models.ForeignKey(
        "Application", on_delete=models.CASCADE, related_name="roles"
    )
    role = models.CharField(
        max_length=50,
        choices=ROLE_CHOICES,
        help_text="User's role for this application (permissions auto-assigned)",
    )
    permissions = models.JSONField(
        default=list,
        blank=True,
        help_text="Auto-assigned based on role. Can be manually overridden if needed.",
    )
    assigned_date = models.DateTimeField(auto_now_add=True)
    notes = models.TextField(blank=True)

    class Meta:
        unique_together = ["user", "application"]
        verbose_name = "Application Role"
        verbose_name_plural = "Application Roles"
        db_table = "sso_application_roles"

    def save(self, *args, **kwargs):
        """
        Auto-assign permissions based on role if not explicitly set or role changed.

        Behavior:
        - New records: Auto-assign permissions if field is empty
        - Role changes: Auto-update permissions if they match old role defaults
        - Manual override: If permissions differ from old defaults, preserve them
        """
        # Check if this is an update to an existing record
        if self.pk:
            try:
                old_instance = ApplicationRole.objects.get(pk=self.pk)

                # If role changed, check if we should auto-update permissions
                if old_instance.role != self.role:
                    old_default_perms = self.ROLE_PERMISSIONS.get(old_instance.role, [])

                    # Only auto-update if old permissions matched old role's defaults
                    # This preserves manual customizations while fixing the primary bug
                    if old_instance.permissions == old_default_perms:
                        self.permissions = self.ROLE_PERMISSIONS.get(self.role, [])
                    # else: old permissions were customized, keep current value

            except ApplicationRole.DoesNotExist:
                pass

        # For new records, auto-assign if permissions field is empty
        if not self.permissions:
            self.permissions = self.ROLE_PERMISSIONS.get(self.role, [])

        super().save(*args, **kwargs)

    def has_permission(self, permission):
        """
        Check if this role has a specific permission.

        Args:
            permission (str): Permission to check (e.g., 'write', 'delete')

        Returns:
            bool: True if role has the permission

        Example:
            role.has_permission('write')  # True for Admin and Office, False for Client
            role.has_permission('delete')  # True for Admin and Office, False for Client
        """
        if "full_access" in self.permissions:
            return True
        return permission in self.permissions

    def __str__(self):
        user_id = self.user.email or self.user.anonymous_username
        return (
            f"{user_id} - {self.get_application_display()}: "
            f"{self.get_role_display()}"
        )


class RefreshToken(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="refresh_tokens"
    )
    application = models.ForeignKey(
        Application, on_delete=models.CASCADE, related_name="refresh_tokens"
    )
    token = models.TextField(unique=True)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "sso_refresh_tokens"
        ordering = ["-created_at"]


class TokenExchangeSession(models.Model):
    """Temporary secure storage for OAuth tokens during exchange.

    This model prevents token exposure in URLs by using a two-step exchange:
    1. OAuth callback creates session with tokens
    2. Frontend exchanges session_id for tokens via API

    Security features:
    - Single-use sessions (used flag)
    - 60-second expiry
    - Session ID is UUID (non-guessable)
    - Automatic cleanup of expired sessions
    """

    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    access_token = models.TextField()
    refresh_token = models.TextField()
    user_email = models.EmailField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)

    class Meta:
        db_table = "sso_token_exchange_sessions"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["expires_at", "used"]),
        ]

    def __str__(self):
        return f"Exchange session for {self.user_email} (used: {self.used})"

    def is_valid(self):
        """Check if session is still valid for exchange."""
        from django.utils import timezone

        return not self.used and self.expires_at > timezone.now()


class LoginAttempt(models.Model):
    """Track failed login attempts for account lockout protection.

    Security features:
    - Tracks failed login attempts by identifier (email/username)
    - 15-minute lockout after 5 failed attempts
    - Automatic cleanup after 24 hours
    - IP address logging for security analysis
    """

    identifier = models.CharField(
        max_length=255, db_index=True
    )  # email or anonymous_username
    ip_address = models.GenericIPAddressField()
    attempted_at = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=False)

    class Meta:
        db_table = "sso_login_attempts"
        ordering = ["-attempted_at"]
        indexes = [
            models.Index(fields=["identifier", "attempted_at"]),
            models.Index(fields=["ip_address", "attempted_at"]),
        ]

    def __str__(self):
        status = "successful" if self.success else "failed"
        return (
            f"{status} login attempt for {self.identifier} from "
            f"{self.ip_address} at {self.attempted_at}"
        )


class PasswordResetToken(models.Model):
    """
    Secure password reset tokens with expiration and one-time use.

    Security features:
    - Tokens are hashed before storage (never store plaintext)
    - 32-character hex tokens (128 bits of entropy)
    - 1-hour expiration
    - One-time use (marked as used after successful reset)
    - IP address tracking for audit
    - Created timestamp for expiration validation
    """

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="password_reset_tokens"
    )
    token_hash = models.CharField(
        max_length=64, unique=True, help_text="SHA256 hash of the reset token"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text="Token expiration time (1 hour from creation)"
    )
    used_at = models.DateTimeField(
        null=True, blank=True, help_text="When the token was used (null if unused)"
    )
    ip_address = models.GenericIPAddressField(
        help_text="IP address that requested the reset"
    )

    class Meta:
        db_table = "sso_password_reset_tokens"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["token_hash"]),
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["expires_at"]),
        ]

    def __str__(self):
        status = (
            "used" if self.used_at else ("expired" if self.is_expired() else "valid")
        )
        return f"Password reset for {self.user.email} - {status}"

    def save(self, *args, **kwargs):
        """Set expiration time on creation (1 hour from now)"""
        if not self.pk and not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=1)
        super().save(*args, **kwargs)

    def is_expired(self):
        """Check if token has expired"""
        return timezone.now() > self.expires_at

    def is_valid(self):
        """Check if token is valid (not expired, not used)"""
        return not self.used_at and not self.is_expired()

    def mark_as_used(self):
        """Mark token as used (one-time use enforcement)"""
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])

    @classmethod
    def generate_token(cls, user, ip_address):
        """
        Generate a secure reset token for the user.

        Returns tuple: (token_string, token_object)
        - token_string: 32-char hex to send in email (plaintext, one-time view)
        - token_object: PasswordResetToken instance (stores hash only)
        """
        import hashlib

        # Generate 32-character hex token (128 bits entropy)
        token_string = secrets.token_hex(16)  # 16 bytes = 32 hex chars

        # Hash the token for storage (SHA256)
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()

        # Create token record
        token_obj = cls.objects.create(
            user=user, token_hash=token_hash, ip_address=ip_address
        )

        return token_string, token_obj

    @classmethod
    def validate_token(cls, token_string):
        """
        Validate a reset token.

        Returns:
        - PasswordResetToken object if valid
        - None if invalid/expired/used
        """
        import hashlib

        # Hash the provided token
        token_hash = hashlib.sha256(token_string.encode()).hexdigest()

        # Find matching token
        try:
            token = cls.objects.get(token_hash=token_hash)

            # Check if valid
            if token.is_valid():
                return token
            else:
                return None

        except cls.DoesNotExist:
            return None

    @classmethod
    def cleanup_expired(cls):
        """Delete expired tokens (run periodically via management command)"""
        expired_count = cls.objects.filter(expires_at__lt=timezone.now()).delete()[0]
        return expired_count
