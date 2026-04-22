"""Tests for the provision_tenant management command (bind-to-existing mode)."""

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

roles:
  - code: testapp_tstp_admin
    name: "TestApp TSTP Admin"
    legacy_role: Admin
  - code: testapp_tstp_viewer
    name: "TestApp TSTP Viewer"
    legacy_role: Client

users:
  - email: alice@tstp.example.com
    first_name: Alice
    last_name: Anderson
    role: testapp_tstp_admin
    auth_type: google
  - email: bob@tstp.example.com
    first_name: Bob
    last_name: Brown
    role: testapp_tstp_viewer
    auth_type: google
"""


def _yaml_with_users(users_block: str) -> str:
    """Build a YAML with a single role and a custom users block (indented correctly)."""
    return (
        "tenant_code: TSTE\n"
        'display_name: "Test Email"\n'
        "application_slug: testapp\n"
        "roles:\n"
        "  - code: testapp_tste_client\n"
        '    name: "TestApp TSTE Client"\n'
        "    legacy_role: Client\n"
        "users:\n" + users_block
    )


class ProvisionTenantTestBase(TestCase):
    """Shared setup: temp dir for YAML + audit file, actor user, target Application.

    Every test gets a pre-existing OAuth Application with slug='testapp' to
    bind to. Tests that need a different pre-existing app can create one
    explicitly.
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

        # Target Application exists from setUp — no new Application created.
        self.assertEqual(Application.objects.count(), 1)
        self.assertEqual(Role.objects.count(), 0)
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
    def test_happy_path_creates_everything(self):
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        # No new Application created — the target one is reused.
        self.assertEqual(Application.objects.count(), 1)
        app = Application.objects.get(slug="testapp")
        self.assertEqual(app.id, self.target_app.id)

        # Roles attach to the pre-existing target Application.
        self.assertEqual(Role.objects.filter(application=app).count(), 2)
        for role in Role.objects.filter(application=app):
            self.assertEqual(role.application.slug, "testapp")

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

    def test_uar_role_application_matches_resolved(self):
        """Critical integration check: every UserAppRole.role.application must
        equal the resolved target Application — otherwise the JWT wouldn't
        surface the role for logins on that Application."""
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        for uar in UserAppRole.objects.all():
            self.assertEqual(uar.role.application.slug, "testapp")
            self.assertEqual(uar.role.application.id, self.target_app.id)


class IdempotencyTests(ProvisionTenantTestBase):
    def test_idempotent_rerun(self):
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

        audit = self._audit_lines()
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[1]["bindings_created"], 0)


class ValidationTests(ProvisionTenantTestBase):
    def test_invalid_yaml_missing_field(self):
        bad = VALID_YAML.replace("tenant_code: TSTP\n", "")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("tenant_code", str(ctx.exception))

    def test_invalid_role_reference(self):
        bad = VALID_YAML.replace("role: testapp_tstp_admin", "role: testapp_tstp_ghost")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        self.assertIn("testapp_tstp_ghost", msg)

    def test_invalid_tenant_code(self):
        bad = VALID_YAML.replace("tenant_code: TSTP", "tenant_code: tstp-bad")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("tenant_code", str(ctx.exception))


class ApplicationSlugTests(ProvisionTenantTestBase):
    """New-schema tests for application_slug: required, must resolve to an
    existing Application, and Roles attach to that resolved Application."""

    def test_application_slug_required(self):
        bad = VALID_YAML.replace("application_slug: testapp\n", "")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("application_slug", str(ctx.exception))
        # Nothing written
        self.assertEqual(Role.objects.count(), 0)
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
        # The existing target_app slug appears in the list
        self.assertIn("testapp", msg)
        # Nothing written
        self.assertEqual(Role.objects.count(), 0)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)

    def test_application_slug_not_found_on_dry_run(self):
        """Dry-run must also surface the missing-slug error; operators should
        never discover bad slugs only at real-run time."""
        bad = VALID_YAML.replace(
            "application_slug: testapp", "application_slug: nonexistent"
        )
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--dry-run")
        self.assertIn("nonexistent", str(ctx.exception))

    def test_application_slug_resolves_existing(self):
        """With multiple candidate Applications present, the slug must pick
        the right one — Roles attach to the chosen App, not the other one."""
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
        cfg = self._write_yaml(VALID_YAML)
        self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        # Roles attach to testapp, not otherapp
        self.assertEqual(Role.objects.filter(application=self.target_app).count(), 2)
        self.assertEqual(Role.objects.filter(application=other_app).count(), 0)

    def test_application_slug_invalid_format_rejected(self):
        """Schema-level rejection: uppercase slug, underscore, trailing hyphen."""
        for bad_slug in ("TestApp", "test_app", "testapp-"):
            with self.subTest(slug=bad_slug):
                bad = VALID_YAML.replace(
                    "application_slug: testapp", f"application_slug: {bad_slug}"
                )
                cfg = self._write_yaml(bad)
                with self.assertRaises(CommandError) as ctx:
                    self._run("--config", cfg, "--actor", "clif@barge2rail.com")
                self.assertIn("application_slug", str(ctx.exception))


class NoClientSecretBannerTests(ProvisionTenantTestBase):
    """This command never creates Applications, so client_secret must never
    appear in command output."""

    def test_no_client_secret_banner_real_run(self):
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertNotIn("client_secret", out.lower())
        self.assertNotIn("COPY THIS NOW", out.split("Email/password users", 1)[0])

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
        # UserAppRole was assigned by the case-insensitive-resolved actor
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

        # All writes rolled back: Roles, Users, Bindings, Tenant.
        # The target Application is unaffected (not created by this run).
        self.assertEqual(Role.objects.count(), 0)
        self.assertEqual(
            User.objects.filter(
                email__in=["alice@tstp.example.com", "bob@tstp.example.com"]
            ).count(),
            0,
        )
        self.assertEqual(UserAppRole.objects.count(), 0)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)

        # Target Application still there
        self.assertEqual(Application.objects.filter(slug="testapp").count(), 1)

        # No audit line written (audit happens after successful commit)
        self.assertEqual(self._audit_lines(), [])


class EmailAuthTests(ProvisionTenantTestBase):
    """Tests for the auth_type: email user creation path."""

    EMAIL_USER_YAML = _yaml_with_users(
        "  - email: briana@marianshipping.example.com\n"
        "    first_name: Briana\n"
        "    last_name: Jackson\n"
        "    role: testapp_tste_client\n"
        "    auth_type: email\n"
    )

    GOOGLE_USER_YAML = _yaml_with_users(
        "  - email: staff@barge2rail.com\n"
        "    first_name: Staff\n"
        "    last_name: Person\n"
        "    role: testapp_tste_client\n"
        "    auth_type: google\n"
    )

    DEFAULT_AUTH_YAML = _yaml_with_users(
        "  - email: noauth@example.com\n"
        "    first_name: Default\n"
        "    last_name: Auth\n"
        "    role: testapp_tste_client\n"
        # auth_type omitted on purpose
    )

    MIXED_YAML = _yaml_with_users(
        "  - email: briana@marianshipping.example.com\n"
        "    first_name: Briana\n"
        "    last_name: Jackson\n"
        "    role: testapp_tste_client\n"
        "    auth_type: email\n"
        "  - email: staff@barge2rail.com\n"
        "    first_name: Staff\n"
        "    last_name: Person\n"
        "    role: testapp_tste_client\n"
        "    auth_type: google\n"
    )

    ANON_YAML = _yaml_with_users(
        "  - email: anon@example.com\n"
        "    first_name: Anon\n"
        "    last_name: User\n"
        "    role: testapp_tste_client\n"
        "    auth_type: anonymous\n"
    )

    @staticmethod
    def _extract_password_for(stdout: str, email: str) -> str:
        """Find the password printed next to an email in the credentials banner."""
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
        self.assertEqual(Role.objects.count(), 0)

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

    def test_idempotent_rerun_email_user(self):
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

        # DB side effects succeeded
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
            "    role: testapp_tste_client\n"
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
            "    role: testapp_tste_client\n"
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
            "    role: testapp_tste_client\n"
            "    auth_type: google\n"
        )
        cfg = self._write_yaml(yaml_content)

        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        msg = str(ctx.exception)
        self.assertIn("Multiple users", msg)
        self.assertIn("bob@example.com", msg)

        # Nothing else created
        self.assertEqual(Role.objects.count(), 0)
        self.assertEqual(UserAppRole.objects.count(), 0)
        self.assertEqual(Tenant.objects.filter(code="TSTE").count(), 0)
