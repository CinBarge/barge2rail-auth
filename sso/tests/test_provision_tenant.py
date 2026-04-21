"""Tests for the provision_tenant management command."""

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

application:
  name: "CBRTConnect - TSTP"
  redirect_uris:
    - https://example.com/oauth/callback/

roles:
  - code: cbrtconnect_tstp_admin
    name: "CBRTConnect TSTP Admin"
    legacy_role: Admin
  - code: cbrtconnect_tstp_viewer
    name: "CBRTConnect TSTP Viewer"
    legacy_role: Client

users:
  - email: alice@tstp.example.com
    first_name: Alice
    last_name: Anderson
    role: cbrtconnect_tstp_admin
    auth_type: google
  - email: bob@tstp.example.com
    first_name: Bob
    last_name: Brown
    role: cbrtconnect_tstp_viewer
    auth_type: google
"""


def _yaml_with_users(users_block: str) -> str:
    """Build a YAML with a single role and a custom users block (indented correctly)."""
    return (
        "tenant_code: TSTE\n"
        'display_name: "Test Email"\n'
        "application:\n"
        '  name: "CBRTConnect - TSTE"\n'
        "  redirect_uris:\n"
        "    - https://example.com/oauth/callback/\n"
        "roles:\n"
        "  - code: cbrtconnect_tste_client\n"
        '    name: "CBRTConnect TSTE Client"\n'
        "    legacy_role: Client\n"
        "users:\n" + users_block
    )


class ProvisionTenantTestBase(TestCase):
    """Shared setup: temp dir for YAML + audit file, actor user."""

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

        self.assertEqual(Application.objects.count(), 0)
        self.assertEqual(Role.objects.count(), 0)
        # Only users that should exist: the actor we created in setUp plus
        # any seeded by migrations. Neither of the YAML's users should exist.
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
        self.assertEqual(self._audit_lines(), [])


class HappyPathTests(ProvisionTenantTestBase):
    def test_happy_path_creates_everything(self):
        cfg = self._write_yaml(VALID_YAML)
        out = self._run("--config", cfg, "--actor", "clif@barge2rail.com")

        self.assertEqual(
            Application.objects.filter(name="CBRTConnect - TSTP").count(), 1
        )
        app = Application.objects.get(name="CBRTConnect - TSTP")
        self.assertEqual(app.slug, "cbrtconnect-tstp")
        self.assertEqual(app.user, self.actor)

        self.assertEqual(Role.objects.filter(application=app).count(), 2)
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

        self.assertIn("COPY THIS NOW", out)
        self.assertIn(app.client_id, out)

        audit = self._audit_lines()
        self.assertEqual(len(audit), 1)
        rec = audit[0]
        self.assertEqual(rec["tenant_code"], "TSTP")
        self.assertEqual(rec["actor"], "clif@barge2rail.com")
        self.assertEqual(
            sorted(rec["users_created"]),
            ["alice@tstp.example.com", "bob@tstp.example.com"],
        )
        self.assertEqual(rec["bindings_created"], 2)
        self.assertNotIn("client_secret", rec)
        self.assertNotIn("client_id", rec)


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
        self.assertNotIn("COPY THIS NOW", out)

        audit = self._audit_lines()
        self.assertEqual(len(audit), 2)
        self.assertEqual(audit[1]["bindings_created"], 0)
        self.assertTrue(audit[1]["application_skipped"])


class ValidationTests(ProvisionTenantTestBase):
    def test_invalid_yaml_missing_field(self):
        bad = VALID_YAML.replace("tenant_code: TSTP\n", "")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("tenant_code", str(ctx.exception))

    def test_invalid_role_reference(self):
        bad = VALID_YAML.replace(
            "role: cbrtconnect_tstp_admin", "role: cbrtconnect_tstp_ghost"
        )
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        msg = str(ctx.exception)
        self.assertIn("cbrtconnect_tstp_ghost", msg)

    def test_invalid_tenant_code(self):
        bad = VALID_YAML.replace("tenant_code: TSTP", "tenant_code: tstp-bad")
        cfg = self._write_yaml(bad)
        with self.assertRaises(CommandError) as ctx:
            self._run("--config", cfg, "--actor", "clif@barge2rail.com")
        self.assertIn("tenant_code", str(ctx.exception))


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
        app = Application.objects.get(name="CBRTConnect - TSTP")
        self.assertEqual(app.user, self.actor)


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

        # All writes rolled back
        self.assertEqual(
            Application.objects.filter(name="CBRTConnect - TSTP").count(), 0
        )
        self.assertEqual(Role.objects.count(), 0)
        self.assertEqual(
            User.objects.filter(
                email__in=["alice@tstp.example.com", "bob@tstp.example.com"]
            ).count(),
            0,
        )
        self.assertEqual(UserAppRole.objects.count(), 0)
        self.assertEqual(Tenant.objects.filter(code="TSTP").count(), 0)

        # No audit line written (audit happens after successful commit)
        self.assertEqual(self._audit_lines(), [])


class EmailAuthTests(ProvisionTenantTestBase):
    """Tests for the auth_type: email user creation path."""

    EMAIL_USER_YAML = _yaml_with_users(
        "  - email: briana@marianshipping.example.com\n"
        "    first_name: Briana\n"
        "    last_name: Jackson\n"
        "    role: cbrtconnect_tste_client\n"
        "    auth_type: email\n"
    )

    GOOGLE_USER_YAML = _yaml_with_users(
        "  - email: staff@barge2rail.com\n"
        "    first_name: Staff\n"
        "    last_name: Person\n"
        "    role: cbrtconnect_tste_client\n"
        "    auth_type: google\n"
    )

    DEFAULT_AUTH_YAML = _yaml_with_users(
        "  - email: noauth@example.com\n"
        "    first_name: Default\n"
        "    last_name: Auth\n"
        "    role: cbrtconnect_tste_client\n"
        # auth_type omitted on purpose
    )

    MIXED_YAML = _yaml_with_users(
        "  - email: briana@marianshipping.example.com\n"
        "    first_name: Briana\n"
        "    last_name: Jackson\n"
        "    role: cbrtconnect_tste_client\n"
        "    auth_type: email\n"
        "  - email: staff@barge2rail.com\n"
        "    first_name: Staff\n"
        "    last_name: Person\n"
        "    role: cbrtconnect_tste_client\n"
        "    auth_type: google\n"
    )

    ANON_YAML = _yaml_with_users(
        "  - email: anon@example.com\n"
        "    first_name: Anon\n"
        "    last_name: User\n"
        "    role: cbrtconnect_tste_client\n"
        "    auth_type: anonymous\n"
    )

    @staticmethod
    def _extract_password_for(stdout: str, email: str) -> str:
        """Find the password printed next to an email in the credentials banner."""
        for raw in stdout.splitlines():
            stripped = raw.strip()
            if stripped.startswith(email):
                parts = stripped.split()
                # Line format: "<email>  <password>"
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
        self.assertGreaterEqual(len(temp_password), 20)  # token_urlsafe(18) ~= 24 chars
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
        # Defense-in-depth: field names that would leak secrets
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

        # Credentials banner lists only the email user
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
        # Nothing should have been created
        self.assertEqual(
            Application.objects.filter(name="CBRTConnect - TSTE").count(), 0
        )

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
        # Existing auth_type preserved, not clobbered
        self.assertEqual(user.auth_type, "google")
        self.assertFalse(user.has_usable_password())
        # No temp password printed for a SKIP'd user
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
        # Password not rotated on re-run
        self.assertTrue(user.check_password(original_password))
