"""YAML schema for `provision_tenant`. Not a public API — leading underscore.

Validation is strict: unknown fields are rejected, role references must resolve,
and every string that looks like a URL or email is parsed, not just regex-matched.
"""

from __future__ import annotations

import re
from typing import List

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

TENANT_CODE_RE = re.compile(r"^[A-Z0-9]{1,10}$")
# Django-style slug: lowercase alphanumeric + hyphens, no leading/trailing
# hyphens, 2-64 chars. Matches the existing prod convention (primetrade,
# cbrtconnect-dev, etc.).
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$")
# Pragmatic email regex: good enough to catch typos in hand-written YAML.
# Deep RFC 5322 conformance would require the email-validator package (not a
# current dep) and is overkill for a human-reviewed config file.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class RoleSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=50)
    name: str = Field(min_length=1, max_length=100)
    legacy_role: str = Field(min_length=1, max_length=50)


class UserSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    first_name: str = Field(min_length=1, max_length=150)
    last_name: str = Field(min_length=1, max_length=150)
    role: str = Field(min_length=1, max_length=50)
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


class ApplicationSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    # Optional. When omitted, the command layer defaults to tenant_code.lower()
    # (bare slug), matching the existing prod convention. When provided,
    # operators can override for any reason (legacy rename, special casing, etc.)
    slug: str | None = None
    redirect_uris: List[HttpUrl] = Field(min_length=1)

    @field_validator("slug")
    @classmethod
    def _check_slug(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not SLUG_RE.match(v):
            raise ValueError(
                "slug must be lowercase alphanumeric with hyphens, "
                "e.g. 'msp' or 'cbrtconnect-dev' "
                "(no uppercase, no underscores, no leading/trailing hyphens, "
                "2-64 chars)"
            )
        return v


class TenantConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_code: str
    display_name: str = Field(min_length=1, max_length=100)
    application: ApplicationSpec
    roles: List[RoleSpec] = Field(min_length=1)
    users: List[UserSpec] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_tenant_code(self) -> "TenantConfig":
        if not TENANT_CODE_RE.match(self.tenant_code):
            raise ValueError(
                f"tenant_code '{self.tenant_code}' must match {TENANT_CODE_RE.pattern} "
                "(uppercase letters/digits, 1-10 chars)"
            )
        return self

    @model_validator(mode="after")
    def _check_role_codes_unique(self) -> "TenantConfig":
        seen: set[str] = set()
        for i, role in enumerate(self.roles):
            if role.code in seen:
                raise ValueError(f"roles.{i}.code: duplicate role code '{role.code}'")
            seen.add(role.code)
        return self

    @model_validator(mode="after")
    def _check_user_role_refs(self) -> "TenantConfig":
        valid_codes = {r.code for r in self.roles}
        for i, user in enumerate(self.users):
            if user.role not in valid_codes:
                raise ValueError(
                    f"users.{i}.role: unknown role '{user.role}' "
                    f"(not in roles[].code: {sorted(valid_codes)})"
                )
        return self

    @model_validator(mode="after")
    def _check_user_emails_unique(self) -> "TenantConfig":
        seen: set[str] = set()
        for i, user in enumerate(self.users):
            # EmailStr comparison is case-sensitive; normalize for the dup check only.
            normalized = str(user.email).lower()
            if normalized in seen:
                raise ValueError(f"users.{i}.email: duplicate email '{user.email}'")
            seen.add(normalized)
        return self
