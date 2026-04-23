"""YAML schema for `provision_tenant`. Not a public API — leading underscore.

Schema (v3, bind-to-existing-roles mode):
- Top-level `application_slug` names an EXISTING OAuth Application.
- Each user's `role_code` names an EXISTING Role on that Application.
- This command does not create OAuth Applications, Roles, Features, or
  RoleFeaturePermissions. Register apps via /cbrt-ops/ first; create Roles
  via admin or the `setup_rbac` command.

v3 BREAKING CHANGE from v2 (PR #14):
- Removed top-level `roles:` block (the tool no longer creates Roles).
- Per-user field renamed `role:` → `role_code:` to make the bind-to-existing
  semantics explicit at the call site.
"""

from __future__ import annotations

import re

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

TENANT_CODE_RE = re.compile(r"^[A-Z0-9]{1,10}$")
# Django-style slug: lowercase alphanumeric + hyphens, no leading/trailing
# hyphens, 2-50 chars. Matches the existing prod convention (primetrade,
# cbrtconnect-dev, etc.) and the Application.slug SlugField(max_length=50)
# constraint.
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,48}[a-z0-9]$")
# Pragmatic email regex: good enough to catch typos in hand-written YAML.
# Deep RFC 5322 conformance would require the email-validator package (not a
# current dep) and is overkill for a human-reviewed config file.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


# Surfaced before pydantic validation so operators get a v3-specific message
# instead of a generic "extra fields not permitted" pydantic error.
LEGACY_ROLES_KEY_MESSAGE = (
    "'roles:' is no longer supported in provision_tenant YAML as of v3. "
    "Roles must exist on the target Application before provisioning. "
    "Reference them via each user's role_code. If you need a new Role, "
    "create it via admin or the setup_rbac command first."
)


class UserSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    first_name: str = Field(min_length=1, max_length=150)
    last_name: str = Field(min_length=1, max_length=150)
    # Code of an EXISTING Role on the target Application. The command resolves
    # this against Role.objects.filter(application=app, code=role_code) and
    # errors out (listing valid codes) if missing.
    role_code: str = Field(min_length=1, max_length=50)
    # Defaults to 'email' because client users (the common case) are not Google
    # Workspace accounts. Staff using Google SSO must set this explicitly.
    auth_type: str = Field(default="email")

    @field_validator("email")
    @classmethod
    def _check_email(cls, v: str) -> str:
        if not EMAIL_RE.match(v):
            raise ValueError(f"'{v}' does not look like a valid email address")
        return v

    @field_validator("auth_type")
    @classmethod
    def _check_auth_type(cls, v: str) -> str:
        if v == "anonymous":
            raise ValueError(
                "auth_type 'anonymous' is not supported by provision_tenant "
                "(requires a PIN field and a different flow; create anonymous "
                "users via /cbrt-ops/ admin instead)"
            )
        if v not in ("email", "google"):
            raise ValueError(f"auth_type must be 'email' or 'google', got '{v}'")
        return v


class TenantConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_code: str
    display_name: str = Field(min_length=1, max_length=100)
    # Slug of an EXISTING OAuth Application. UserAppRoles bind users to Roles
    # on that Application, scoped by tenant_code. The Application itself is
    # NOT created here — register it via /cbrt-ops/ first.
    application_slug: str = Field(min_length=2, max_length=50)
    users: list[UserSpec] = Field(min_length=1)

    @field_validator("application_slug")
    @classmethod
    def _check_application_slug(cls, v: str) -> str:
        if not SLUG_RE.match(v):
            raise ValueError(
                "application_slug must be lowercase alphanumeric with hyphens, "
                "e.g. 'sacks' or 'cbrtconnect-dev' "
                "(no uppercase, no underscores, no leading/trailing hyphens, "
                "2-50 chars)"
            )
        return v

    @model_validator(mode="after")
    def _check_tenant_code(self) -> "TenantConfig":
        if not TENANT_CODE_RE.match(self.tenant_code):
            raise ValueError(
                f"tenant_code '{self.tenant_code}' must match {TENANT_CODE_RE.pattern} "
                "(uppercase letters/digits, 1-10 chars)"
            )
        return self

    @model_validator(mode="after")
    def _check_user_emails_unique(self) -> "TenantConfig":
        seen: set[str] = set()
        for i, user in enumerate(self.users):
            normalized = str(user.email).lower()
            if normalized in seen:
                raise ValueError(f"users.{i}.email: duplicate email '{user.email}'")
            seen.add(normalized)
        return self
