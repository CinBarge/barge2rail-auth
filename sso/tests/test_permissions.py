"""
Unit tests for sso.utils.permissions module

Tests email whitelist validation and permission assignment logic.
"""

from django.test import TestCase, override_settings
from django.contrib.auth import get_user_model
from sso.utils.permissions import (
    should_grant_admin_access,
    should_grant_superuser_access,
    get_admin_whitelist,
    get_superuser_whitelist,
    assign_admin_permissions,
    revoke_admin_permissions,
)

User = get_user_model()


class GetAdminWhitelistTests(TestCase):
    """Test get_admin_whitelist function."""

    @override_settings(ADMIN_WHITELIST='admin@example.com,user@example.com')
    def test_parse_comma_separated_list(self):
        """Test parsing comma-separated email list."""
        whitelist = get_admin_whitelist()
        self.assertEqual(len(whitelist), 2)
        self.assertIn('admin@example.com', whitelist)
        self.assertIn('user@example.com', whitelist)

    @override_settings(ADMIN_WHITELIST='Admin@Example.COM,USER@example.com')
    def test_lowercase_conversion(self):
        """Test emails are lowercased."""
        whitelist = get_admin_whitelist()
        self.assertIn('admin@example.com', whitelist)
        self.assertIn('user@example.com', whitelist)

    @override_settings(ADMIN_WHITELIST=' admin@example.com , user@example.com ')
    def test_whitespace_stripping(self):
        """Test whitespace is stripped from emails."""
        whitelist = get_admin_whitelist()
        self.assertEqual(len(whitelist), 2)
        self.assertIn('admin@example.com', whitelist)

    @override_settings(ADMIN_WHITELIST='admin@example.com,,*@domain.com,')
    def test_empty_entries_filtered(self):
        """Test empty entries are filtered out."""
        whitelist = get_admin_whitelist()
        self.assertEqual(len(whitelist), 2)
        self.assertNotIn('', whitelist)

    @override_settings(ADMIN_WHITELIST='*@barge2rail.com,admin@example.com')
    def test_wildcard_support(self):
        """Test wildcard domains are included."""
        whitelist = get_admin_whitelist()
        self.assertIn('*@barge2rail.com', whitelist)

    @override_settings(ADMIN_WHITELIST='')
    def test_empty_whitelist(self):
        """Test empty whitelist returns empty list."""
        whitelist = get_admin_whitelist()
        self.assertEqual(whitelist, [])

    def test_missing_setting(self):
        """Test missing ADMIN_WHITELIST setting."""
        # Remove setting if exists
        if hasattr(self._testMethodName, 'ADMIN_WHITELIST'):
            delattr(self._testMethodName, 'ADMIN_WHITELIST')

        whitelist = get_admin_whitelist()
        self.assertEqual(whitelist, [])


class GetSuperuserWhitelistTests(TestCase):
    """Test get_superuser_whitelist function."""

    @override_settings(SUPERUSER_WHITELIST='admin@example.com,superadmin@example.com')
    def test_parse_comma_separated_list(self):
        """Test parsing comma-separated email list."""
        whitelist = get_superuser_whitelist()
        self.assertEqual(len(whitelist), 2)
        self.assertIn('admin@example.com', whitelist)
        self.assertIn('superadmin@example.com', whitelist)

    @override_settings(SUPERUSER_WHITELIST='*@barge2rail.com,admin@example.com')
    def test_wildcards_removed(self):
        """Test wildcards are removed from superuser whitelist (security)."""
        whitelist = get_superuser_whitelist()
        # Should only have exact email, wildcard removed
        self.assertNotIn('*@barge2rail.com', whitelist)
        self.assertIn('admin@example.com', whitelist)
        self.assertEqual(len(whitelist), 1)

    @override_settings(SUPERUSER_WHITELIST='')
    def test_empty_whitelist(self):
        """Test empty whitelist returns empty list."""
        whitelist = get_superuser_whitelist()
        self.assertEqual(whitelist, [])


class ShouldGrantAdminAccessTests(TestCase):
    """Test should_grant_admin_access function."""

    @override_settings(ADMIN_WHITELIST='admin@example.com,user@example.com')
    def test_exact_email_match(self):
        """Test exact email match grants access."""
        self.assertTrue(should_grant_admin_access('admin@example.com'))
        self.assertTrue(should_grant_admin_access('user@example.com'))

    @override_settings(ADMIN_WHITELIST='admin@example.com')
    def test_case_insensitive_match(self):
        """Test case-insensitive email matching."""
        self.assertTrue(should_grant_admin_access('Admin@Example.COM'))
        self.assertTrue(should_grant_admin_access('ADMIN@EXAMPLE.COM'))

    @override_settings(ADMIN_WHITELIST='*@barge2rail.com')
    def test_domain_wildcard_match(self):
        """Test domain wildcard matching."""
        self.assertTrue(should_grant_admin_access('user@barge2rail.com'))
        self.assertTrue(should_grant_admin_access('admin@barge2rail.com'))
        self.assertTrue(should_grant_admin_access('anyone@barge2rail.com'))

    @override_settings(ADMIN_WHITELIST='*@barge2rail.com')
    def test_domain_wildcard_no_subdomain_match(self):
        """Test wildcard doesn't match subdomains."""
        self.assertFalse(should_grant_admin_access('user@sub.barge2rail.com'))

    @override_settings(ADMIN_WHITELIST='*@barge2rail.com')
    def test_domain_wildcard_different_domain(self):
        """Test wildcard doesn't match different domains."""
        self.assertFalse(should_grant_admin_access('user@evil.com'))

    @override_settings(ADMIN_WHITELIST='admin@example.com,*@barge2rail.com')
    def test_mixed_exact_and_wildcard(self):
        """Test mixed exact and wildcard whitelist."""
        # Exact match
        self.assertTrue(should_grant_admin_access('admin@example.com'))
        # Wildcard match
        self.assertTrue(should_grant_admin_access('user@barge2rail.com'))
        # No match
        self.assertFalse(should_grant_admin_access('user@evil.com'))

    @override_settings(ADMIN_WHITELIST='admin@example.com')
    def test_non_whitelisted_email_denied(self):
        """Test non-whitelisted email is denied."""
        self.assertFalse(should_grant_admin_access('hacker@evil.com'))

    @override_settings(ADMIN_WHITELIST='')
    def test_empty_whitelist_denies_all(self):
        """Test empty whitelist denies all access."""
        self.assertFalse(should_grant_admin_access('admin@example.com'))

    @override_settings(ADMIN_WHITELIST='admin@example.com')
    def test_empty_email_denied(self):
        """Test empty email is denied."""
        self.assertFalse(should_grant_admin_access(''))
        self.assertFalse(should_grant_admin_access(None))

    @override_settings(ADMIN_WHITELIST=' admin@example.com ')
    def test_whitespace_handling(self):
        """Test whitespace in email is handled."""
        self.assertTrue(should_grant_admin_access(' admin@example.com '))


class ShouldGrantSuperuserAccessTests(TestCase):
    """Test should_grant_superuser_access function."""

    @override_settings(SUPERUSER_WHITELIST='admin@example.com')
    def test_exact_match_only(self):
        """Test only exact matches grant superuser."""
        self.assertTrue(should_grant_superuser_access('admin@example.com'))

    @override_settings(SUPERUSER_WHITELIST='admin@example.com')
    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        self.assertTrue(should_grant_superuser_access('Admin@Example.COM'))

    @override_settings(SUPERUSER_WHITELIST='admin@barge2rail.com')
    def test_no_wildcard_support(self):
        """Test wildcards don't work for superuser (security)."""
        # Even if wildcard in list, it's removed by get_superuser_whitelist
        self.assertTrue(should_grant_superuser_access('admin@barge2rail.com'))
        self.assertFalse(should_grant_superuser_access('user@barge2rail.com'))

    @override_settings(SUPERUSER_WHITELIST='admin@example.com')
    def test_different_email_denied(self):
        """Test different email is denied."""
        self.assertFalse(should_grant_superuser_access('user@example.com'))

    @override_settings(SUPERUSER_WHITELIST='')
    def test_empty_whitelist_denies_all(self):
        """Test empty whitelist denies all superuser access."""
        self.assertFalse(should_grant_superuser_access('admin@example.com'))

    @override_settings(SUPERUSER_WHITELIST='admin@example.com')
    def test_empty_email_denied(self):
        """Test empty email is denied."""
        self.assertFalse(should_grant_superuser_access(''))
        self.assertFalse(should_grant_superuser_access(None))


class AssignAdminPermissionsTests(TestCase):
    """Test assign_admin_permissions function."""

    def setUp(self):
        """Create test users."""
        self.user = User.objects.create(
            email='test@example.com',
            username='testuser',
            is_staff=False,
            is_superuser=False,
        )

    @override_settings(
        ADMIN_WHITELIST='test@example.com',
        SUPERUSER_WHITELIST=''
    )
    def test_grant_staff_access(self):
        """Test granting staff access."""
        is_staff, is_superuser, changed = assign_admin_permissions(self.user)

        self.assertTrue(is_staff)
        self.assertFalse(is_superuser)
        self.assertTrue(changed)

        # Reload from database
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)

    @override_settings(
        ADMIN_WHITELIST='test@example.com',
        SUPERUSER_WHITELIST='test@example.com'
    )
    def test_grant_superuser_access(self):
        """Test granting superuser access."""
        is_staff, is_superuser, changed = assign_admin_permissions(self.user)

        self.assertTrue(is_staff)
        self.assertTrue(is_superuser)
        self.assertTrue(changed)

        # Reload from database
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_staff)
        self.assertTrue(self.user.is_superuser)

    @override_settings(
        ADMIN_WHITELIST='test@example.com',
        SUPERUSER_WHITELIST='test@example.com'
    )
    def test_no_change_if_already_correct(self):
        """Test no update if permissions already correct."""
        # Set permissions first
        self.user.is_staff = True
        self.user.is_superuser = True
        self.user.save()

        # Assign again
        is_staff, is_superuser, changed = assign_admin_permissions(self.user)

        self.assertTrue(is_staff)
        self.assertTrue(is_superuser)
        self.assertFalse(changed)  # No change

    @override_settings(
        ADMIN_WHITELIST='',
        SUPERUSER_WHITELIST=''
    )
    def test_no_access_if_not_whitelisted(self):
        """Test no permissions granted if not whitelisted."""
        is_staff, is_superuser, changed = assign_admin_permissions(self.user)

        self.assertFalse(is_staff)
        self.assertFalse(is_superuser)
        self.assertFalse(changed)

    @override_settings(
        ADMIN_WHITELIST='*@example.com',
        SUPERUSER_WHITELIST=''
    )
    def test_wildcard_grants_staff_not_superuser(self):
        """Test wildcard grants staff but not superuser."""
        is_staff, is_superuser, changed = assign_admin_permissions(self.user)

        self.assertTrue(is_staff)
        self.assertFalse(is_superuser)

    def test_invalid_user_returns_false(self):
        """Test invalid user returns False."""
        result = assign_admin_permissions(None)
        self.assertEqual(result, (False, False, False))

    def test_user_without_email(self):
        """Test user without email returns False."""
        user = User.objects.create(
            username='noemail',
            email='',  # No email
        )
        result = assign_admin_permissions(user)
        self.assertEqual(result, (False, False, False))


class RevokeAdminPermissionsTests(TestCase):
    """Test revoke_admin_permissions function."""

    def test_revoke_from_admin_user(self):
        """Test revoking permissions from admin user."""
        user = User.objects.create(
            email='admin@example.com',
            username='admin',
            is_staff=True,
            is_superuser=True,
        )

        changed = revoke_admin_permissions(user)

        self.assertTrue(changed)
        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_revoke_from_staff_only(self):
        """Test revoking from staff-only user."""
        user = User.objects.create(
            email='staff@example.com',
            username='staff',
            is_staff=True,
            is_superuser=False,
        )

        changed = revoke_admin_permissions(user)

        self.assertTrue(changed)
        user.refresh_from_db()
        self.assertFalse(user.is_staff)

    def test_revoke_from_regular_user(self):
        """Test revoking from regular user (no change)."""
        user = User.objects.create(
            email='user@example.com',
            username='user',
            is_staff=False,
            is_superuser=False,
        )

        changed = revoke_admin_permissions(user)

        self.assertFalse(changed)
        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_invalid_user(self):
        """Test invalid user returns False."""
        changed = revoke_admin_permissions(None)
        self.assertFalse(changed)

    def test_idempotent(self):
        """Test multiple revocations are idempotent."""
        user = User.objects.create(
            email='admin@example.com',
            username='admin',
            is_staff=True,
            is_superuser=True,
        )

        # First revocation
        changed1 = revoke_admin_permissions(user)
        self.assertTrue(changed1)

        # Second revocation (no change)
        changed2 = revoke_admin_permissions(user)
        self.assertFalse(changed2)
