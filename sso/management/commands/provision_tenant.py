"""Provision a new tenant: Application + Roles + Users + UserAppRole bindings.

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

from ._tenant_schema import TenantConfig


class Command(BaseCommand):
    help = "Provision a tenant (Application, Roles, Users, UserAppRoles) from a YAML config."

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

        # Banners FIRST — secrets must reach the operator even if audit I/O fails.
        # DB records are already committed; if we hid the banner behind an I/O
        # failure, the operator would have a provisioned tenant with no
        # recoverable client_secret or temp passwords.
        if result["client_secret_plaintext"]:
            self._print_secret_banner(
                result["client_id"], result["client_secret_plaintext"]
            )
        elif result["application_skipped"]:
            self.stdout.write(
                self.style.WARNING(
                    "\nApplication already existed; client_secret was only shown on original creation. "
                    "If lost, rotate via /cbrt-ops/."
                )
            )

        if result["email_user_credentials"]:
            self._print_email_credentials_banner(result["email_user_credentials"])

        # Audit LAST. Warn-and-continue on I/O failure; provisioning succeeded
        # and the secrets have been shown, so don't mislead the operator with a
        # non-zero exit.
        try:
            self._append_audit(cfg, actor, result, dry_run=False)
        except OSError as e:
            self.stderr.write(
                self.style.WARNING(
                    f"Audit log write failed: {e}. "
                    "Provisioning succeeded; any secrets were displayed above."
                )
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"\nDone. Tenant '{cfg.tenant_code}' provisioned "
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

    # ---- plan --------------------------------------------------------------

    def _build_plan(self, cfg: TenantConfig) -> Dict[str, Any]:
        slug = self._derive_slug(cfg.tenant_code)

        tenant = Tenant.objects.filter(code=cfg.tenant_code).first()
        app = Application.objects.filter(name=cfg.application.name).first()

        # Finding 3: reject mismatched slug BEFORE any writes (and before
        # dry-run returns a misleading SKIP plan). Catches copy-paste errors
        # where tenant_code was changed but application.name was not.
        if app is not None and app.slug != slug:
            raise CommandError(
                f"Application '{cfg.application.name}' already exists with slug "
                f"'{app.slug}' but this YAML implies slug '{slug}'. "
                f"Either the tenant_code or the application.name is wrong. "
                f"Refusing to reuse the existing application."
            )

        roles_plan: List[Dict[str, Any]] = []
        if app:
            existing_role_codes = set(
                Role.objects.filter(application=app).values_list("code", flat=True)
            )
        else:
            existing_role_codes = set()
        for r in cfg.roles:
            roles_plan.append({"spec": r, "exists": r.code in existing_role_codes})

        # Finding 2: normalize emails and look up case-insensitively. A legacy
        # DB row with mixed-case email matches a lowercase YAML entry; if two
        # rows differ only by case (historical data), fail fast.
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
            role_exists = u.role in existing_role_codes
            binding_exists = False
            if app and user_obj and role_exists:
                role_obj = Role.objects.filter(application=app, code=u.role).first()
                if role_obj:
                    binding_exists = UserAppRole.objects.filter(
                        user=user_obj, role=role_obj, tenant_code=cfg.tenant_code
                    ).exists()
            bindings_plan.append(
                {"email": email_str, "role": u.role, "exists": binding_exists}
            )

        return {
            "slug": slug,
            "tenant_exists": tenant is not None,
            "app_exists": app is not None,
            "roles": roles_plan,
            "users": users_plan,
            "bindings": bindings_plan,
        }

    def _derive_slug(self, tenant_code: str) -> str:
        return f"cbrtconnect-{tenant_code.lower()}"

    def _print_plan(
        self, cfg: TenantConfig, plan: Dict[str, Any], dry_run: bool
    ) -> None:
        header = "DRY-RUN PLAN" if dry_run else "PROVISION PLAN"
        self.stdout.write(
            self.style.MIGRATE_HEADING(f"\n=== {header}: {cfg.tenant_code} ===")
        )

        def line(label: str, exists: bool, detail: str = "") -> None:
            tag = "SKIP (exists)" if exists else "CREATE"
            style = self.style.WARNING if exists else self.style.SUCCESS
            suffix = f"  {detail}" if detail else ""
            self.stdout.write(f"  {style(tag):<25} {label}{suffix}")

        line(
            f"Tenant {cfg.tenant_code!r} ({cfg.display_name!r})", plan["tenant_exists"]
        )
        line(
            f"Application {cfg.application.name!r} slug={plan['slug']!r}",
            plan["app_exists"],
        )
        for rp in plan["roles"]:
            line(
                f"Role {rp['spec'].code!r} (legacy={rp['spec'].legacy_role!r})",
                rp["exists"],
            )
        for up in plan["users"]:
            detail = f"auth_type={up['spec'].auth_type}"
            if up["auth_type_mismatch"]:
                detail += f"  [auth_type mismatch: {up['auth_type_mismatch']} - existing row NOT modified]"
            line(f"User {up['email']!r}", up["exists"], detail)
        for bp in plan["bindings"]:
            line(
                f"UserAppRole user={bp['email']!r} role={bp['role']!r} tenant={cfg.tenant_code!r}",
                bp["exists"],
            )

    # ---- execute -----------------------------------------------------------

    def _execute(
        self, cfg: TenantConfig, plan: Dict[str, Any], actor: User
    ) -> Dict[str, Any]:
        slug = plan["slug"]

        # Tenant
        Tenant.objects.get_or_create(
            code=cfg.tenant_code,
            defaults={"name": cfg.display_name, "is_active": True},
        )

        # Application
        app = Application.objects.filter(name=cfg.application.name).first()
        client_secret_plaintext: str | None = None
        application_skipped = True
        if app is None:
            application_skipped = False
            client_id = self._gen_unique_client_id()
            client_secret_plaintext = secrets.token_urlsafe(48)
            redirect_uris = "\n".join(str(u) for u in cfg.application.redirect_uris)
            app = Application(
                name=cfg.application.name,
                slug=slug,
                client_id=client_id,
                client_secret=client_secret_plaintext,
                redirect_uris=redirect_uris,
                client_type=Application.CLIENT_CONFIDENTIAL,
                authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
                user=actor,
            )
            app.save()

        # Roles
        roles_created: List[str] = []
        role_objs: Dict[str, Role] = {}
        for r in cfg.roles:
            role_obj = Role.objects.filter(application=app, code=r.code).first()
            if role_obj is None:
                role_obj = Role.objects.create(
                    application=app,
                    code=r.code,
                    name=r.name,
                    legacy_role=r.legacy_role,
                    is_active=True,
                )
                roles_created.append(r.code)
            role_objs[r.code] = role_obj

        # Users — emails are normalized to lowercase on creation, and
        # existence checks are case-insensitive so a legacy mixed-case DB row
        # still matches a lowercase YAML entry.
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

        # Bindings
        bindings_created = 0
        for u in cfg.users:
            email_str = str(u.email).strip().lower()
            user_obj = user_objs[email_str]
            role_obj = role_objs[u.role]
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
            "application_skipped": application_skipped,
            "client_id": app.client_id if not application_skipped else None,
            "client_secret_plaintext": client_secret_plaintext,
            "roles_created": roles_created,
            "users_created": users_created,
            "bindings_created": bindings_created,
            "email_user_credentials": email_user_credentials,
        }

    def _gen_unique_client_id(self) -> str:
        while True:
            candidate = f"app_{secrets.token_hex(8)}"
            if not Application.objects.filter(client_id=candidate).exists():
                return candidate

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
            "application_skipped": result["application_skipped"],
            "roles_created": result["roles_created"],
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

    def _print_secret_banner(self, client_id: str, client_secret: str) -> None:
        bar = "=" * 64
        self.stdout.write("\n" + bar)
        self.stdout.write("COPY THIS NOW - IT WILL NOT BE SHOWN AGAIN")
        self.stdout.write(bar)
        self.stdout.write(f"client_id:     {client_id}")
        self.stdout.write(f"client_secret: {client_secret}")
        self.stdout.write(bar)

    def _print_email_credentials_banner(
        self, credentials: List[tuple[str, str]]
    ) -> None:
        bar = "=" * 64
        self.stdout.write("\n" + bar)
        self.stdout.write("COPY THIS NOW - IT WILL NOT BE SHOWN AGAIN")
        self.stdout.write(
            "Email/password users (temp passwords - distribute privately):"
        )
        self.stdout.write(bar)
        email_width = max(len(e) for e, _ in credentials)
        for email, password in credentials:
            self.stdout.write(f"  {email:<{email_width}}  {password}")
        self.stdout.write(bar)
        self.stdout.write(
            "Users should change these at https://sso.barge2rail.com/change-password/ on first login."
        )
