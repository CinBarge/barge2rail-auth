"""Tests for the provision_tenant management command (v3 bind-to-existing-roles).

v3 contract under test:
- Command does NOT create OAuth Applications (inherited from v2).
- Command does NOT create Roles (NEW in v3 — was the v2 behavior).
- Command resolves each user's `role_code` against existing Roles on the
  target Application; missing role_code errors out with all offending users
  listed in one message.
- Top-level `roles:` key from v2 is rejected with a v3-specific message.
"""

from __future__ import annotations

import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from sso.models import Application, Role, Tenant, User, UserAppRole

VALID_YAML = """
tenant_code: TSTP
display_name: "Test Provision"

application_slug: testapp

users:
  - email: alice@tstp.example.com
    first_name: Alice
    last_name: Anderson
    role_code: testapp_admin
    auth_type: google
  - email: bob@tstp.example.com
    first_name: Bob
    last_name: Brown
    role_code: testapp_client
    auth_type: google
"""


def _yaml_with_users(users_block: str) -> str:
    """Build a YAML with a single tenant and a custom users block (indented correctly)."""
    return (
        "tenant_code: TSTE\n"
        'display_name: "Test Email"\n'
        "application_slug: testapp\n"
        "users:\n" + users_block
    )


class ProvisionTenantTestBase(TestCase):
    """Shared setup: temp dir for YAML + audit file, actor user, target
    Application, and two pre-existing Roles on that Application.

    Every test gets:
      - `self.target_app` — Application(slug='testapp')
      - `self.role_admin` — Role(application=target_app, code='testapp_admin')
      - `self.role_client` — Role(application=target_app, code='testapp_client')

    These are the role_codes referenced by VALID_YAML. v3 will not create
    Roles itself, so they must exist before any happy-path test runs.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = Path(self._tmp.name)
        self.audit_override = override_settings(LOGS_DIR=self.tmp_path)
        self.audit_override.enable()
        self.addCleanup(self.audit_override.disable)

        self.actor = User.objects.create_user(
            email="clif@barge2rail.com",
            first_name="Clif",
            last_name="Badante",
            auth_type="google",
            auth_method="google",
        )

        self.target_app = Application.objects.create(
            name="TestApp",
            slug="testapp",
            client_id="app_testapp_0001",
            client_secret="testapp-secret-not-real",  # pragma: allowlist secret
            redirect_uris="https://example.com/oauth/callback/",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=self.actor,
        )

        self.role_admin = Role.objects.create(
            application=self.target_app,
            code="testapp_admin",
            name="TestApp Admin",
            legacy_role="Admin",
            is_active=True,
        )
        self.role_client = Role.objects.create(
            application=self.target_app,
            code="testapp_client",
            name="TestApp Client",
            legacy_role="Client",
            is_active=True,
        )
        # Snapshot of pre-existing Role count so tests can assert "no new
        # Roles created" without hardcoding the number.
        self._initial_role_count = Role.objects.count()

    def _write_yaml(self, content: str, name: str = "tenant.yaml") -> str:
        p = self.tmp_path / name
        p.write_text(content)
        return str(p)

    def _run(self, *args, expect_success: bool = True) -> str:
        out, err = StringIO(), StringIO()
        try:
            call_command("provision_tenant", *args, stdout=out, stderr=err)
        except CommandError:
            if expect_success:
                raise
            raise
        return out.getvalue()

    def _audit_lines(self) -> list[dict]:
        path = self.tmp_path / "tenant_provisioning.jsonl"
        if not path.exists():
            return []
        return [
            json.loads(line) for line in path.read_text().splitlines() if line.strip()
        ]


class DryRunTests(ProvisionTenantTestBase):
    def test_dry_run_creates_nothing(self):
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--dry-run")

        self.assertEqual(Application.objects.count(), 1)
        self.assertEqual(Role.objects.count(), self._initial_role_count)
        self.assertEqual(
            User.objects.filter(
                email__in=["alice@tstp.example.com", "bob@tstp.example.com"]
            ).count(),
            0,
        )
        self.assertEqual(UserAppRole.objects.count(), 0)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)
        self.assertIn("CREATE", out)
        self.assertIn("DRY-RUN PLAN", out)
        self.assertIn("Bound to Application:", out)
        self.assertIn("'testapp'", out)
        self.assertEqual(self._audit_lines(), [])


class HappyPathTests(ProvisionTenantTestBase):
    def test_happy_path_creates_users_and_bindings_no_roles(self):
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        # No new Application, no new Roles.
        self.assertEqual(Application.objects.count(), 1)
        self.assertEqual(Role.objects.count(), self._initial_role_count)

        # Users + bindings + tenant created.
        self.assertEqual(
            User.objects.filter(
                email__in=["alice@tstp.example.com", "bob@tstp.example.com"]
            ).count(),
            2,
        )
        self.assertEqual(UserAppRole.objects.filter(tenant_code="TSTP").count(), 2)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 1)

        alice = User.objects.get(email="alice@tstp.example.com")
        self.assertEqual(alice.auth_type, "google")
        self.assertFalse(alice.has_usable_password())

        # No client_secret banner — we don't create Applications.
        self.assertNotIn("client_secret", out.lower())

    def test_happy_path_audit_record(self):
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        audit = self._audit_lines()
        self.assertEqual(len(audit), 1)
        rec = audit[0]
        self.assertEqual(rec["tenant_code"], "TSTP")
        self.assertEqual(rec["actor"], "clif@barge2rail.com")
        self.assertEqual(rec["application_slug"], "testapp")
        self.assertEqual(
            sorted(rec["users_created"]),
            ["alice@tstp.example.com", "bob@tstp.example.com"],
        )
        self.assertEqual(rec["bindings_created"], 2)
        self.assertNotIn("client_secret", rec)
        # v3: no roles_created field — the command doesn't create Roles.
        self.assertNotIn("roles_created", rec)

    def test_uar_role_application_matches_resolved(self):
        """Critical integration check: every UserAppRole.role.application must
        equal the resolved target Application — otherwise the JWT wouldn't
        surface the role for logins on that Application."""
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        for uar in UserAppRole.objects.all():
            self.assertEqual(uar.role.application.slug, "testapp")
            self.assertEqual(uar.role.application.id, self.target_app.id)

    def test_uar_binds_to_pre_existing_role_objects(self):
        """The bindings must reference the EXACT pre-existing Role rows, not
        new ones — confirms 'bind to existing' semantics."""
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        alice_uar = UserAppRole.objects.get(user__email="alice@tstp.example.com")
        bob_uar = UserAppRole.objects.get(user__email="bob@tstp.example.com")
        self.assertEqual(alice_uar.role_id, self.role_admin.id)
        self.assertEqual(bob_uar.role_id, self.role_client.id)


class IdempotencyTests(ProvisionTenantTestBase):
    def test_idempotent_rerun_no_new_writes(self):
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        app_count = Application.objects.count()
        role_count = Role.objects.count()
        user_count = User.objects.count()
        binding_count = UserAppRole.objects.count()

        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        self.assertEqual(Application.objects.count(), app_count)
        self.assertEqual(Role.objects.count(), role_count)
        self.assertEqual(User.objects.count(), user_count)
        self.assertEqual(UserAppRole.objects.count(), binding_count)
        self.assertIn("SKIP (exists)", out)

    def test_idempotent_audit_records_zero_bindings(self):
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        audit = self._audit_lines()
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[1]["bindings_created"], 0)
        self.assertEqual(audit[1]["users_created"], [])


class RoleResolutionTests(ProvisionTenantTestBase):
    """v3-specific: the command must look up each user's role_code against
    existing Roles on the target Application, accumulate ALL missing-role
    failures, and write nothing if any are missing."""

    def test_unknown_role_code_errors(self):
        bad = VALID_YAML.replace("role_code: testapp_admin", "role_code: testapp_ghost")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        self.assertIn("testapp_ghost", msg)
        self.assertIn("alice@tstp.example.com", msg)

    def test_unknown_role_code_error_lists_existing_codes(self):
        bad = VALID_YAML.replace("role_code: testapp_admin", "role_code: testapp_ghost")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--dry-run")
        msg = str(ctx.exception)
        self.assertIn("Existing role codes", msg)
        self.assertIn("testapp_admin", msg)
        self.assertIn("testapp_client", msg)

    def test_multiple_missing_role_codes_all_reported(self):
        """If two users reference missing Roles, the error must name BOTH
        users in one message — not stop at the first."""
        bad = VALID_YAML.replace(
            "role_code: testapp_admin", "role_code: testapp_ghost1"
        ).replace("role_code: testapp_client", "role_code: testapp_ghost2")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        self.assertIn("testapp_ghost1", msg)
        self.assertIn("testapp_ghost2", msg)
        self.assertIn("alice@tstp.example.com", msg)
        self.assertIn("bob@tstp.example.com", msg)

    def test_no_db_writes_on_unknown_role_code(self):
        bad = VALID_YAML.replace("role_code: testapp_admin", "role_code: testapp_ghost")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError):
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertEqual(Role.objects.count(), self._initial_role_count)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)
        self.assertEqual(
            User.objects.filter(
                email__in=["alice@tstp.example.com", "bob@tstp.example.com"]
            ).count(),
            0,
        )
        self.assertEqual(UserAppRole.objects.count(), 0)
        self.assertEqual(self._audit_lines(), [])

    def test_unknown_role_code_dry_run_also_errors(self):
        """Operators must discover bad role_codes at dry-run time, not real-run time."""
        bad = VALID_YAML.replace("role_code: testapp_admin", "role_code: testapp_ghost")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--dry-run")
        self.assertIn("testapp_ghost", str(ctx.exception))

    def test_role_must_belong_to_target_application_not_another(self):
        """A Role with the right code on a DIFFERENT Application must not
        satisfy a binding on the resolved Application."""
        other_app = Application.objects.create(
            name="OtherApp",
            slug="otherapp",
            client_id="app_other_0002",
            client_secret="other-secret-not-real",  # pragma: allowlist secret
            redirect_uris="https://example.com/oauth/callback/",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=self.actor,
        )
        # Create a Role on otherapp with the code the YAML wants — but the
        # YAML targets testapp, so this should NOT satisfy.
        Role.objects.create(
            application=other_app,
            code="testapp_only_on_other",
            name="On Other Only",
            legacy_role="Admin",
            is_active=True,
        )
        bad = VALID_YAML.replace(
            "role_code: testapp_admin", "role_code: testapp_only_on_other"
        )
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("testapp_only_on_other", str(ctx.exception))


class LegacyRolesKeyTests(ProvisionTenantTestBase):
    """v2 YAMLs include a top-level `roles:` block. v3 must reject these with
    a specific, actionable error message — not a generic pydantic 'extra
    fields' error."""

    LEGACY_V2_YAML = """
tenant_code: TSTP
display_name: "Legacy v2"

application_slug: testapp

roles:
  - code: testapp_admin
    name: "TestApp Admin"
    legacy_role: Admin

users:
  - email: alice@tstp.example.com
    first_name: Alice
    last_name: Anderson
    role: testapp_admin
    auth_type: google
"""

    def test_legacy_roles_key_rejected_with_v3_message(self):
        cfg = self._write_yaml(self.LEGACY_V2_YAML)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        self.assertIn("'roles:'", msg)
        self.assertIn("v3", msg)
        self.assertIn("role_code", msg)

    def test_legacy_roles_key_rejected_dry_run(self):
        cfg = self._write_yaml(self.LEGACY_V2_YAML)
        with self.assertRaises(CommandError):
            self._run("--config", cfg, "--dry-run")

    def test_legacy_roles_key_no_writes(self):
        cfg = self._write_yaml(self.LEGACY_V2_YAML)
        with self.assertRaises(CommandError):
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)
        self.assertEqual(User.objects.filter(email="alice@tstp.example.com").count(), 0)
        self.assertEqual(UserAppRole.objects.count(), 0)


class ApplicationSlugTests(ProvisionTenantTestBase):
    """application_slug: required, must resolve to an existing Application."""

    def test_application_slug_required(self):
        bad = VALID_YAML.replace("application_slug: testapp\n", "")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("application_slug", str(ctx.exception))
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)

    def test_application_slug_not_found(self):
        bad = VALID_YAML.replace(
            "application_slug: testapp", "application_slug: nonexistent"
        )
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        self.assertIn("nonexistent", msg)
        self.assertIn("Existing slugs", msg)
        self.assertIn("testapp", msg)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)

    def test_application_slug_not_found_on_dry_run(self):
        bad = VALID_YAML.replace(
            "application_slug: testapp", "application_slug: nonexistent"
        )
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--dry-run")
        self.assertIn("nonexistent", str(ctx.exception))

    def test_application_slug_resolves_existing(self):
        """With multiple candidate Applications present, the slug must pick
        the right one — bindings attach to the chosen App's Roles, not the other."""
        other_app = Application.objects.create(
            name="OtherApp",
            slug="otherapp",
            client_id="app_other_0002",
            client_secret="other-secret-not-real",  # pragma: allowlist secret
            redirect_uris="https://example.com/oauth/callback/",
            client_type=Application.CLIENT_CONFIDENTIAL,
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            user=self.actor,
        )
        # Same role code on the wrong app — must not satisfy bindings for testapp.
        Role.objects.create(
            application=other_app,
            code="testapp_admin",
            name="Wrong App Admin",
            legacy_role="Admin",
            is_active=True,
        )
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        for uar in UserAppRole.objects.all():
            self.assertEqual(uar.role.application_id, self.target_app.id)
            self.assertNotEqual(uar.role.application_id, other_app.id)

    def test_application_slug_invalid_format_rejected(self):
        for bad_slug in ("TestApp", "test_app", "testapp-"):
            with self.subTest(slug=bad_slug):
                bad = VALID_YAML.replace(
                    "application_slug: testapp", f"application_slug: {bad_slug}"
                )
                cfg = self._write_yaml(bad)
                with self.assertRaises(CommandError) as ctx:
                    self._run("--config", cfg, "--actor", "clif@barge2rail.com")
                self.assertIn("application_slug", str(ctx.exception))


class ValidationTests(ProvisionTenantTestBase):
    def test_invalid_yaml_missing_tenant_code(self):
        bad = VALID_YAML.replace("tenant_code: TSTP\n", "")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("tenant_code", str(ctx.exception))

    def test_invalid_tenant_code_format(self):
        bad = VALID_YAML.replace("tenant_code: TSTP", "tenant_code: tstp-bad")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("tenant_code", str(ctx.exception))

    def test_unknown_top_level_key_rejected(self):
        bad = VALID_YAML + "\nschema_version: 3\n"
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("schema_version", str(ctx.exception))

    def test_unknown_user_field_rejected(self):
        bad = VALID_YAML.replace(
            "    role_code: testapp_admin",
            "    role_code: testapp_admin\n    surprise: true",
            1,
        )
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("surprise", str(ctx.exception))

    def test_old_role_field_name_rejected(self):
        """A v2 YAML inside a v3 schema (no top-level roles:, but per-user
        `role:` instead of `role_code:`) must be rejected."""
        bad = VALID_YAML.replace("role_code:", "role:")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        # Pydantic flags `role` as extra (forbidden) AND `role_code` as missing.
        self.assertTrue("role" in msg)

    def test_duplicate_emails_rejected(self):
        bad = VALID_YAML.replace("bob@tstp.example.com", "alice@tstp.example.com")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("duplicate email", str(ctx.exception))

    def test_role_code_field_required(self):
        bad = VALID_YAML.replace("    role_code: testapp_admin\n", "")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("role_code", str(ctx.exception))


class TenantTests(ProvisionTenantTestBase):
    def test_tenant_get_or_create_when_missing(self):
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        tenant = Tenant.objects.get(code="TSTP")
        self.assertEqual(tenant.name, "Test Provision")
        self.assertTrue(tenant.is_active)

    def test_existing_tenant_with_different_display_name_not_overwritten(self):
        Tenant.objects.create(code="TSTP", name="Pre-existing Name", is_active=True)
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        tenant = Tenant.objects.get(code="TSTP")
        self.assertEqual(tenant.name, "Pre-existing Name")
        self.assertIn("display_name mismatch", out)


class NoClientSecretBannerTests(ProvisionTenantTestBase):
    """This command never creates Applications, so client_secret must never
    appear in command output."""

    def test_no_client_secret_banner_real_run(self):
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertNotIn("client_secret", out.lower())
        self.assertNotIn("COPY THIS NOW", out)  # no email users in VALID_YAML

    def test_no_client_secret_banner_dry_run(self):
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--dry-run")
        self.assertNotIn("client_secret", out.lower())
        self.assertNotIn("COPY THIS NOW", out)


class AuditFieldsTests(ProvisionTenantTestBase):
    def test_audit_records_application_slug(self):
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        audit = self._audit_lines()
        self.assertEqual(len(audit), 1)
        self.assertEqual(audit[0]["application_slug"], "testapp")
        self.assertEqual(audit[0]["application_id"], str(self.target_app.id))
        self.assertEqual(audit[0]["application_name"], "TestApp")

    def test_audit_has_no_roles_created_field(self):
        """v3 doesn't create Roles, so the audit record must not pretend it might."""
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        audit = self._audit_lines()
        self.assertNotIn("roles_created", audit[0])


class ActorTests(ProvisionTenantTestBase):
    def test_missing_actor_real_run(self):
        cfg = self._write_yaml(VALID_YAML)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg)
        self.assertIn("--actor", str(ctx.exception))

    def test_actor_with_dry_run_rejected(self):
        cfg = self._write_yaml(VALID_YAML)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--dry-run", "--actor", "clif@barge2rail.com")
        self.assertIn("--actor", str(ctx.exception))

    def test_unknown_actor(self):
        cfg = self._write_yaml(VALID_YAML)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "ghost@barge2rail.com")
        self.assertIn("ghost@barge2rail.com", str(ctx.exception))

    def test_actor_case_insensitive(self):
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "CLIF@BARGE2RAIL.COM")
        uar = UserAppRole.objects.first()
        self.assertEqual(uar.assigned_by, self.actor)


class RollbackTests(ProvisionTenantTestBase):
    def test_rollback_on_mid_transaction_failure(self):
        cfg = self._write_yaml(VALID_YAML)
        call_count = {"n": 0}
        real_save = UserAppRole.save

        def boom(self, *args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise RuntimeError("simulated DB failure")
            return real_save(self, *args, **kwargs)

        with mock.patch.object(UserAppRole, "save", boom):
            with self.assertRaises(RuntimeError):
                self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        # All writes rolled back. The pre-existing target Application and
        # Roles are unaffected (this run never created them).
        self.assertEqual(Role.objects.count(), self._initial_role_count)
        self.assertEqual(
            User.objects.filter(
                email__in=["alice@tstp.example.com", "bob@tstp.example.com"]
            ).count(),
            0,
        )
        self.assertEqual(UserAppRole.objects.count(), 0)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)

        self.assertEqual(Application.objects.filter(slug="testapp").count(), 1)
        self.assertEqual(self._audit_lines(), [])


class EmailAuthTests(ProvisionTenantTestBase):
    """auth_type: email user creation. The role_code 'testapp_client' is
    pre-seeded by the base setUp."""

    EMAIL_USER_YAML = _yaml_with_users(
        "  - email: briana@marianshipping.example.com\n"
        "    first_name: Briana\n"
        "    last_name: Jackson\n"
        "    role_code: testapp_client\n"
        "    auth_type: email\n"
    )

    GOOGLE_USER_YAML = _yaml_with_users(
        "  - email: staff@barge2rail.com\n"
        "    first_name: Staff\n"
        "    last_name: Person\n"
        "    role_code: testapp_client\n"
        "    auth_type: google\n"
    )

    DEFAULT_AUTH_YAML = _yaml_with_users(
        "  - email: noauth@example.com\n"
        "    first_name: Default\n"
        "    last_name: Auth\n"
        "    role_code: testapp_client\n"
        # auth_type omitted on purpose
    )

    MIXED_YAML = _yaml_with_users(
        "  - email: briana@marianshipping.example.com\n"
        "    first_name: Briana\n"
        "    last_name: Jackson\n"
        "    role_code: testapp_client\n"
        "    auth_type: email\n"
        "  - email: staff@barge2rail.com\n"
        "    first_name: Staff\n"
        "    last_name: Person\n"
        "    role_code: testapp_client\n"
        "    auth_type: google\n"
    )

    ANON_YAML = _yaml_with_users(
        "  - email: anon@example.com\n"
        "    first_name: Anon\n"
        "    last_name: User\n"
        "    role_code: testapp_client\n"
        "    auth_type: anonymous\n"
    )

    @staticmethod
    def _extract_password_for(stdout: str, email: str) -> str:
        for raw in stdout.splitlines():
            stripped = raw.strip()
            if stripped.startswith(email):
                parts = stripped.split()
                if len(parts) >= 2:
                    return parts[-1]
        raise AssertionError(f"No password line found for {email!r} in stdout")

    def test_email_user_gets_temp_password(self):
        cfg = self._write_yaml(self.EMAIL_USER_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        user = User.objects.get(email="briana@marianshipping.example.com")
        self.assertEqual(user.auth_type, "email")
        self.assertEqual(user.auth_method, "password")
        self.assertTrue(user.has_usable_password())

        self.assertIn("briana@marianshipping.example.com", out)
        self.assertIn("Email/password users", out)
        temp_password = self._extract_password_for(
            out, "briana@marianshipping.example.com"
        )
        self.assertGreaterEqual(len(temp_password), 20)
        self.assertTrue(user.check_password(temp_password))

    def test_email_user_password_not_in_audit(self):
        cfg = self._write_yaml(self.EMAIL_USER_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        temp_password = self._extract_password_for(
            out, "briana@marianshipping.example.com"
        )

        audit_path = self.tmp_path / "tenant_provisioning.jsonl"
        audit_content = audit_path.read_text()
        self.assertNotIn(temp_password, audit_content)
        self.assertNotIn("temp_password", audit_content)
        self.assertNotIn("password", audit_content)

    def test_google_user_unchanged(self):
        cfg = self._write_yaml(self.GOOGLE_USER_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        user = User.objects.get(email="staff@barge2rail.com")
        self.assertEqual(user.auth_type, "google")
        self.assertEqual(user.auth_method, "google")
        self.assertFalse(user.has_usable_password())
        self.assertNotIn("Email/password users", out)

    def test_mixed_yaml_both_auth_types(self):
        cfg = self._write_yaml(self.MIXED_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        briana = User.objects.get(email="briana@marianshipping.example.com")
        staff = User.objects.get(email="staff@barge2rail.com")
        self.assertEqual(briana.auth_type, "email")
        self.assertTrue(briana.has_usable_password())
        self.assertEqual(staff.auth_type, "google")
        self.assertFalse(staff.has_usable_password())

        self.assertIn("Email/password users", out)
        banner_section = out.split("Email/password users", 1)[1]
        self.assertIn("briana@marianshipping.example.com", banner_section)
        self.assertNotIn("staff@barge2rail.com", banner_section)

    def test_default_auth_type_is_email(self):
        cfg = self._write_yaml(self.DEFAULT_AUTH_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        user = User.objects.get(email="noauth@example.com")
        self.assertEqual(user.auth_type, "email")
        self.assertTrue(user.has_usable_password())
        self.assertIn("noauth@example.com", out)

    def test_anonymous_auth_type_rejected(self):
        cfg = self._write_yaml(self.ANON_YAML)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        self.assertIn("auth_type", msg)
        self.assertIn("anonymous", msg)
        self.assertIn("users.0.auth_type", msg)

    def test_existing_google_user_skipped_with_mismatch_warning(self):
        User.objects.create_user(
            email="briana@marianshipping.example.com",
            first_name="Briana",
            last_name="Jackson",
            auth_type="google",
            auth_method="google",
        )
        cfg = self._write_yaml(self.EMAIL_USER_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        self.assertIn("auth_type mismatch", out)
        user = User.objects.get(email="briana@marianshipping.example.com")
        self.assertEqual(user.auth_type, "google")
        self.assertFalse(user.has_usable_password())
        banner_split = out.split("Email/password users")
        if len(banner_split) > 1:
            self.assertNotIn("briana@marianshipping.example.com", banner_split[1])

    def test_idempotent_rerun_email_user_password_unchanged(self):
        cfg = self._write_yaml(self.EMAIL_USER_YAML)
        out1 = self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        original_password = self._extract_password_for(
            out1, "briana@marianshipping.example.com"
        )

        out2 = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        self.assertNotIn("Email/password users", out2)
        user = User.objects.get(email="briana@marianshipping.example.com")
        self.assertTrue(user.check_password(original_password))


class AuditFailureTests(ProvisionTenantTestBase):
    """Banner must print even if audit I/O fails."""

    def test_audit_failure_does_not_block_banner(self):
        cfg = self._write_yaml(EmailAuthTests.EMAIL_USER_YAML)

        out, err = StringIO(), StringIO()
        from sso.management.commands.provision_tenant import Command

        with mock.patch.object(
            Command, "_append_audit", side_effect=OSError("disk full simulation")
        ):
            call_command(
                "provision_tenant",
                "--config",
                cfg,
                "--actor",
                "clif@barge2rail.com",
                stdout=out,
                stderr=err,
            )

        stdout_text = out.getvalue()
        stderr_text = err.getvalue()

        self.assertIn("briana@marianshipping.example.com", stdout_text)
        self.assertIn("Email/password users", stdout_text)
        self.assertIn("Audit log write failed", stderr_text)
        self.assertIn("disk full simulation", stderr_text)

        self.assertEqual(
            User.objects.filter(email="briana@marianshipping.example.com").count(), 1
        )
        self.assertEqual(UserAppRole.objects.count(), 1)


class EmailNormalizationTests(ProvisionTenantTestBase):
    """Email lookups must be case-insensitive and stored lowercased."""

    def test_email_case_normalization_on_create(self):
        yaml_content = _yaml_with_users(
            "  - email: TestUser@Example.COM\n"
            "    first_name: Test\n"
            "    last_name: User\n"
            "    role_code: testapp_client\n"
            "    auth_type: google\n"
        )
        cfg = self._write_yaml(yaml_content)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        self.assertEqual(User.objects.filter(email="testuser@example.com").count(), 1)
        self.assertEqual(User.objects.filter(email="TestUser@Example.COM").count(), 0)
        self.assertIn("testuser@example.com", out)

        audit = self._audit_lines()
        self.assertEqual(audit[0]["users_created"], ["testuser@example.com"])

    def test_email_case_insensitive_idempotency(self):
        base_users = (
            "  - email: alice@example.com\n"
            "    first_name: Alice\n"
            "    last_name: Case\n"
            "    role_code: testapp_client\n"
            "    auth_type: google\n"
        )
        yaml1 = _yaml_with_users(base_users)
        yaml2 = _yaml_with_users(base_users.replace("alice", "Alice", 1))

        cfg1 = self._write_yaml(yaml1, name="yaml1.yaml")
        self._run("--config", cfg1, "--actor", "clif@barge2rail.com")

        cfg2 = self._write_yaml(yaml2, name="yaml2.yaml")
        out = self._run("--config", cfg2, "--actor", "clif@barge2rail.com")

        self.assertIn("SKIP (exists)", out)
        self.assertEqual(
            User.objects.filter(email__iexact="alice@example.com").count(), 1
        )
        self.assertEqual(UserAppRole.objects.count(), 1)

    def test_multiple_users_same_email_different_case(self):
        u1 = User(
            email="bob@example.com",
            first_name="Bob",
            last_name="Lower",
            auth_type="google",
            auth_method="google",
        )
        u1.set_unusable_password()
        u1.save()
        u2 = User(
            email="Bob@example.com",
            first_name="Bob",
            last_name="Upper",
            auth_type="google",
            auth_method="google",
        )
        u2.set_unusable_password()
        u2.save()

        yaml_content = _yaml_with_users(
            "  - email: bob@example.com\n"
            "    first_name: Bob\n"
            "    last_name: Builder\n"
            "    role_code: testapp_client\n"
            "    auth_type: google\n"
        )
        cfg = self._write_yaml(yaml_content)

        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        msg = str(ctx.exception)
        self.assertIn("Multiple users", msg)
        self.assertIn("bob@example.com", msg)

        self.assertEqual(UserAppRole.objects.count(), 0)
        self.assertEqual(Tenant.objects.filter(code="TSTE").count(), 0)
