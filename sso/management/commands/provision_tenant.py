"""Provision a new tenant: bind Users and UserAppRoles to EXISTING Roles on
an EXISTING OAuth Application.

This command does NOT create OAuth Applications, Roles, Features, or
RoleFeaturePermissions. Register the target app via /cbrt-ops/ first.
Create Roles via admin or the `setup_rbac` command.

Usage:
    python manage.py provision_tenant --config tenants/msp.yaml --dry-run
    python manage.py provision_tenant --config tenants/msp.yaml --actor you@barge2rail.com

Idempotent: re-running the same YAML reports SKIP for existing rows and exits 0.
Transactional: any mid-run failure rolls back all writes.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from pydantic import ValidationError

from sso.models import Application, Role, Tenant, User, UserAppRole

from ._tenant_schema import LEGACY_ROLES_KEY_MESSAGE, TenantConfig


class Command(BaseCommand):
    help = (
        "Bind Users and UserAppRoles to EXISTING Roles on an EXISTING OAuth "
        "Application (identified by application_slug in the YAML). Does not "
        "create OAuth Applications or Roles — register apps via /cbrt-ops/ "
        "and create roles via admin or setup_rbac first."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--config", required=True, type=str, help="Path to tenant YAML file"
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Validate and print plan; no DB writes",
        )
        parser.add_argument(
            "--actor",
            type=str,
            default=None,
            help="Email of SSO user performing the provision (required for real run)",
        )

    def handle(self, *args, **options):
        config_path = Path(options["config"])
        dry_run: bool = options["dry_run"]
        actor_email: str | None = options["actor"]

        cfg = self._load_and_validate(config_path)

        if dry_run and actor_email:
            raise CommandError(
                "--actor is not accepted with --dry-run (dry-run performs no writes)"
            )
        if not dry_run and not actor_email:
            raise CommandError("--actor <email> is required for real runs")

        actor = None if dry_run else self._resolve_actor(actor_email)

        plan = self._build_plan(cfg)
        self._print_plan(cfg, plan, dry_run=dry_run)

        if dry_run:
            self.stdout.write(
                self.style.SUCCESS("\nDry-run complete. No changes written.")
            )
            return

        with transaction.atomic():
            result = self._execute(cfg, plan, actor)

        # Banner FIRST — temp passwords must reach the operator even if audit
        # I/O fails. If we hid the banner behind an I/O failure, email users
        # would have no recoverable credentials.
        if result["email_user_credentials"]:
            self._print_email_credentials_banner(
                result["application_slug"], result["email_user_credentials"]
            )

        # Audit LAST. Warn-and-continue on I/O failure; provisioning succeeded
        # and any secrets have been shown, so don't mislead the operator with a
        # non-zero exit.
        try:
            self._append_audit(cfg, actor, result, dry_run=False)
        except OSError as e:
            self.stderr.write(
                self.style.WARNING(
                    f"Audit log write failed: {e}. "
                    "Provisioning succeeded; any temp passwords were displayed above."
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"\nDone. Tenant '{cfg.tenant_code}' bound to Application "
                f"slug='{result['application_slug']}' "
                f"(bindings_created={result['bindings_created']})."
            )
        )

    # ---- load / validate ---------------------------------------------------

    def _load_and_validate(self, config_path: Path) -> TenantConfig:
        if not config_path.exists():
            raise CommandError(f"Config file not found: {config_path}")
        try:
            raw = yaml.safe_load(config_path.read_text())
        except yaml.YAMLError as e:
            raise CommandError(f"YAML parse error in {config_path}: {e}")
        if not isinstance(raw, dict):
            raise CommandError(
                f"{config_path}: top-level YAML must be a mapping, got {type(raw).__name__}"
            )
        # Surface the v3-specific message before pydantic, which would
        # otherwise emit a generic "extra fields not permitted" error and
        # leave the operator wondering what to do about it.
        if "roles" in raw:
            raise CommandError(LEGACY_ROLES_KEY_MESSAGE)
        try:
            return TenantConfig(**raw)
        except ValidationError as e:
            lines = ["YAML validation failed:"]
            for err in e.errors():
                loc = ".".join(str(p) for p in err["loc"])
                lines.append(f"  {loc}: {err['msg']}")
            raise CommandError("\n".join(lines))

    def _resolve_actor(self, email: str) -> User:
        try:
            return User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            raise CommandError(
                f"Actor '{email}' has no SSO user. Create yourself via /cbrt-ops/ first."
            )
        except User.MultipleObjectsReturned:
            raise CommandError(
                f"Multiple users match '{email}' (case-insensitive). "
                "Deduplicate in /cbrt-ops/ before re-running."
            )

    def _resolve_application(self, application_slug: str) -> Application:
        """Look up the target Application by slug. Missing slug is a fatal
        operator error: list the known slugs so the fix is obvious."""
        try:
            return Application.objects.get(slug=application_slug)
        except Application.DoesNotExist:
            existing = sorted(
                Application.objects.values_list("slug", flat=True).exclude(slug="")
            )
            existing_display = ", ".join(existing) if existing else "(none)"
            raise CommandError(
                f"No OAuth Application exists with slug '{application_slug}'. "
                f"Existing slugs: {existing_display}. "
                f"Register the app in /cbrt-ops/ first, or use an existing one."
            )

    # ---- plan --------------------------------------------------------------

    def _build_plan(self, cfg: TenantConfig) -> Dict[str, Any]:
        # Resolve the target Application first — most common failure mode.
        app = self._resolve_application(cfg.application_slug)

        # Resolve every user's Role by code on the target Application. Only
        # ACTIVE Roles count — Role.is_active=False means "do not assign"
        # (model help_text). Distinguish "not found" from "exists but inactive"
        # so the operator gets a specific recovery path (create vs reactivate)
        # instead of a misleading "not found" for a row that's just disabled.
        # Accumulate every offender so a multi-user YAML produces one error
        # listing all problems instead of fixing them one at a time.
        all_roles_on_app = list(Role.objects.filter(application=app))
        active_roles_by_code: Dict[str, Role] = {
            r.code: r for r in all_roles_on_app if r.is_active
        }
        inactive_codes_on_app: set[str] = {
            r.code for r in all_roles_on_app if not r.is_active
        }
        missing_absent: List[str] = []
        missing_inactive: List[str] = []
        for u in cfg.users:
            if u.role_code in active_roles_by_code:
                continue
            email_str = str(u.email).strip().lower()
            if u.role_code in inactive_codes_on_app:
                missing_inactive.append(
                    f"  user '{email_str}' references role '{u.role_code}' "
                    "which exists but is INACTIVE"
                )
            else:
                missing_absent.append(
                    f"  user '{email_str}' references role '{u.role_code}'"
                )
        if missing_absent or missing_inactive:
            existing_codes_display = (
                ", ".join(sorted(active_roles_by_code.keys()))
                if active_roles_by_code
                else "(none)"
            )
            lines = [
                f"Cannot resolve one or more role_code values on Application "
                f"slug='{app.slug}':"
            ]
            if missing_absent:
                lines.append("Not found:")
                lines.extend(missing_absent)
            if missing_inactive:
                lines.append(
                    "Exists but inactive (reactivate in admin, or use a "
                    "different role_code):"
                )
                lines.extend(missing_inactive)
            lines.append(
                f"Existing ACTIVE role codes on '{app.slug}': "
                f"{existing_codes_display}."
            )
            raise CommandError("\n".join(lines))

        tenant = Tenant.objects.filter(code=cfg.tenant_code).first()
        tenant_name_mismatch: str | None = None
        if tenant is not None and tenant.name != cfg.display_name:
            tenant_name_mismatch = f"yaml='{cfg.display_name}', db='{tenant.name}'"

        # Finding 2 (inherited): normalize emails and look up case-insensitively.
        # A legacy DB row with mixed-case email matches a lowercase YAML entry;
        # if two rows differ only by case (historical data), fail fast.
        existing_users: Dict[str, User] = {}
        for u in cfg.users:
            email_str = str(u.email).strip().lower()
            try:
                existing = User.objects.get(email__iexact=email_str)
            except User.DoesNotExist:
                continue
            except User.MultipleObjectsReturned:
                raise CommandError(
                    f"Multiple users match email '{email_str}' (case-insensitive). "
                    "Deduplicate in /cbrt-ops/ before re-running."
                )
            existing_users[email_str] = existing

        users_plan: List[Dict[str, Any]] = []
        for u in cfg.users:
            email_str = str(u.email).strip().lower()
            existing = existing_users.get(email_str)
            mismatch = None
            if existing is not None and existing.auth_type != u.auth_type:
                mismatch = f"yaml={u.auth_type}, db={existing.auth_type}"
            users_plan.append(
                {
                    "spec": u,
                    "email": email_str,
                    "exists": existing is not None,
                    "auth_type_mismatch": mismatch,
                }
            )

        bindings_plan: List[Dict[str, Any]] = []
        for u in cfg.users:
            email_str = str(u.email).strip().lower()
            user_obj = existing_users.get(email_str)
            role_obj = active_roles_by_code[u.role_code]
            binding_exists = False
            if user_obj is not None:
                binding_exists = UserAppRole.objects.filter(
                    user=user_obj, role=role_obj, tenant_code=cfg.tenant_code
                ).exists()
            bindings_plan.append(
                {"email": email_str, "role_code": u.role_code, "exists": binding_exists}
            )

        return {
            "application": app,
            "resolved_roles": active_roles_by_code,
            "tenant_exists": tenant is not None,
            "tenant_name_mismatch": tenant_name_mismatch,
            "users": users_plan,
            "bindings": bindings_plan,
        }

    def _print_plan(
        self, cfg: TenantConfig, plan: Dict[str, Any], dry_run: bool
    ) -> None:
        header = "DRY-RUN PLAN" if dry_run else "PROVISION PLAN"
        app: Application = plan["application"]
        self.stdout.write(
            self.style.MIGRATE_HEADING(f"\n=== {header}: {cfg.tenant_code} ===")
        )
        self.stdout.write(
            f"  Bound to Application: {app.name!r} "
            f"(slug={app.slug!r}, client_id={app.client_id!r})"
        )
        if plan["tenant_name_mismatch"]:
            self.stdout.write(
                self.style.WARNING(
                    f"  Tenant display_name mismatch: {plan['tenant_name_mismatch']} "
                    "(existing row NOT modified)"
                )
            )

        def line(label: str, exists: bool, detail: str = "") -> None:
            tag = "SKIP (exists)" if exists else "CREATE"
            style = self.style.WARNING if exists else self.style.SUCCESS
            suffix = f"  {detail}" if detail else ""
            self.stdout.write(f"  {style(tag):<25} {label}{suffix}")

        line(
            f"Tenant {cfg.tenant_code!r} ({cfg.display_name!r})", plan["tenant_exists"]
        )
        for up in plan["users"]:
            detail = f"auth_type={up['spec'].auth_type}"
            if up["auth_type_mismatch"]:
                detail += f"  [auth_type mismatch: {up['auth_type_mismatch']} - existing row NOT modified]"
            line(f"User {up['email']!r}", up["exists"], detail)
        for bp in plan["bindings"]:
            line(
                f"UserAppRole user={bp['email']!r} role={bp['role_code']!r} "
                f"tenant={cfg.tenant_code!r}",
                bp["exists"],
            )

    # ---- execute -----------------------------------------------------------

    def _execute(
        self, cfg: TenantConfig, plan: Dict[str, Any], actor: User
    ) -> Dict[str, Any]:
        app: Application = plan["application"]
        resolved_roles: Dict[str, Role] = plan["resolved_roles"]

        # Tenant — get_or_create so a pre-existing row with a different
        # display_name is preserved (the plan-printer warns about mismatches).
        Tenant.objects.get_or_create(
            code=cfg.tenant_code,
            defaults={"name": cfg.display_name, "is_active": True},
        )

        # Users — emails normalized to lowercase on creation, existence checks
        # case-insensitive, so a legacy mixed-case DB row matches a lowercase
        # YAML entry.
        users_created: List[str] = []
        user_objs: Dict[str, User] = {}
        email_user_credentials: List[tuple[str, str]] = []
        for u in cfg.users:
            email_str = str(u.email).strip().lower()
            existing = User.objects.filter(email__iexact=email_str).first()
            if existing is None:
                if u.auth_type == "email":
                    temp_password = secrets.token_urlsafe(18)
                    user_obj = User.objects.create_user(
                        email=email_str,
                        password=temp_password,
                        first_name=u.first_name,
                        last_name=u.last_name,
                        display_name=f"{u.first_name} {u.last_name}".strip(),
                        auth_type="email",
                        auth_method="password",
                    )
                    email_user_credentials.append((email_str, temp_password))
                else:
                    user_obj = User.objects.create_user(
                        email=email_str,
                        first_name=u.first_name,
                        last_name=u.last_name,
                        display_name=f"{u.first_name} {u.last_name}".strip(),
                        auth_type="google",
                        auth_method="google",
                    )
                users_created.append(email_str)
            else:
                user_obj = existing
            user_objs[email_str] = user_obj

        # Bindings — bind to the EXISTING resolved Role; never create a Role.
        bindings_created = 0
        for u in cfg.users:
            email_str = str(u.email).strip().lower()
            user_obj = user_objs[email_str]
            role_obj = resolved_roles[u.role_code]
            existing_binding = UserAppRole.objects.filter(
                user=user_obj, role=role_obj, tenant_code=cfg.tenant_code
            ).first()
            if existing_binding is None:
                UserAppRole.objects.create(
                    user=user_obj,
                    role=role_obj,
                    tenant_code=cfg.tenant_code,
                    is_active=True,
                    assigned_by=actor,
                )
                bindings_created += 1

        return {
            "application_id": str(app.id),
            "application_name": app.name,
            "application_slug": app.slug,
            "users_created": users_created,
            "bindings_created": bindings_created,
            "email_user_credentials": email_user_credentials,
        }

    # ---- audit / output ----------------------------------------------------

    def _append_audit(
        self, cfg: TenantConfig, actor: User, result: Dict[str, Any], dry_run: bool
    ) -> None:
        record = {
            "ts": datetime.now(timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z"),
            "actor": actor.email,
            "tenant_code": cfg.tenant_code,
            "application_id": result["application_id"],
            "application_name": result["application_name"],
            "application_slug": result["application_slug"],
            "users_created": result["users_created"],
            "bindings_created": result["bindings_created"],
            "dry_run": dry_run,
        }
        path = Path(settings.LOGS_DIR) / "tenant_provisioning.jsonl"
        first_write = not path.exists()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")
        if first_write:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    def _print_email_credentials_banner(
        self, application_slug: str, credentials: List[tuple[str, str]]
    ) -> None:
        bar = "=" * 64
        self.stdout.write("\n" + bar)
        self.stdout.write("COPY THIS NOW - IT WILL NOT BE SHOWN AGAIN")
        self.stdout.write(
            f"Email/password users bound to Application slug='{application_slug}' "
            f"(temp passwords - distribute privately):"
        )
        self.stdout.write(bar)
        email_width = max(len(e) for e, _ in credentials)
        for email, password in credentials:
            self.stdout.write(f"  {email:<{email_width}}  {password}")
        self.stdout.write(bar)
        self.stdout.write(
            "Users should change these at https://sso.barge2rail.com/change-password/ on first login."
        )
