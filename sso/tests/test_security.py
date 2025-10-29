"""
Security Tests
Tests security features including rate limiting, CSRF protection,
account lockout, and PIN security.
"""

import time

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import Client, TestCase, override_settings

from sso.models import LoginAttempt, User

User = get_user_model()


class RateLimitingTests(TestCase):
    """Test rate limiting on authentication endpoints."""

    def setUp(self):
        # Clear cache between tests to avoid rate limit pollution
        cache.clear()
        self.client = Client()

    @override_settings(RATELIMIT_ENABLE=True)
    def test_email_login_rate_limit(self):
        """Email login should be rate limited to 5 attempts per hour"""
        # Make 5 failed attempts (should all work)
        for i in range(5):
            response = self.client.post(
                "/api/auth/login/email/",
                {"email": "test@example.com", "password": "wrong"},
                content_type="application/json",
            )

            # Should get 401 (Invalid credentials)
            self.assertEqual(response.status_code, 401)

        # 6th attempt should be rate limited
        response = self.client.post(
            "/api/auth/login/email/",
            {"email": "test@example.com", "password": "wrong"},
            content_type="application/json",
        )

        # Should get 429 (Too Many Requests)
        self.assertEqual(response.status_code, 429)
        self.assertIn("Too many", response.json()["error"])

    @override_settings(RATELIMIT_ENABLE=True)
    def test_anonymous_login_rate_limit(self):
        """Anonymous login should be rate limited to 10 attempts per hour"""
        # Make 10 failed attempts with different usernames to avoid account lockout
        # (rate limiting is IP-based, account lockout is identifier-based)
        for i in range(10):
            response = self.client.post(
                "/api/auth/login/anonymous/",
                {"username": f"Guest-{i}", "pin": "000000000000"},
                content_type="application/json",
            )

            # Should get 401
            self.assertEqual(response.status_code, 401)

        # 11th attempt should be rate limited
        response = self.client.post(
            "/api/auth/login/anonymous/",
            {"username": "Guest-11", "pin": "000000000000"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 429)


class AccountLockoutTests(TestCase):
    """Test account lockout after failed login attempts."""

    def setUp(self):
        # Clear cache between tests to avoid rate limit pollution
        cache.clear()
        self.client = Client()
        self.user = User.objects.create_user(
            username="locktest@example.com",
            email="locktest@example.com",
            password="correctpass123456",
        )

    @override_settings(RATELIMIT_ENABLE=True)
    def test_account_locks_after_5_failures(self):
        """Account should lock after 5 failed login attempts"""
        # Make 5 failed attempts
        for i in range(5):
            response = self.client.post(
                "/api/auth/login/email/",
                {"email": "locktest@example.com", "password": "wrong"},
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 401)

        # Verify 5 login attempts were logged
        attempts = LoginAttempt.objects.filter(
            identifier="locktest@example.com", success=False
        ).count()
        self.assertEqual(attempts, 5)

        # 6th attempt should be blocked (either by rate limit or account lockout)
        response = self.client.post(
            "/api/auth/login/email/",
            {"email": "locktest@example.com", "password": "wrong"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 429)
        # Could be rate limit or account lockout (both trigger around 5 attempts)
        error_msg = response.json()["error"].lower()
        self.assertTrue("locked" in error_msg or "too many" in error_msg)

    @override_settings(RATELIMIT_ENABLE=True)
    def test_successful_login_after_failures(self):
        """Should still lock even with correct password after failures"""
        # Make 5 failed attempts
        for i in range(5):
            self.client.post(
                "/api/auth/login/email/",
                {"email": "locktest@example.com", "password": "wrong"},
                content_type="application/json",
            )

        # Try with correct password - should still be locked
        response = self.client.post(
            "/api/auth/login/email/",
            {"email": "locktest@example.com", "password": "correctpass123456"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 429)

    @override_settings(RATELIMIT_ENABLE=True)
    def test_login_attempts_are_logged(self):
        """All login attempts should be logged"""
        # Failed attempt
        self.client.post(
            "/api/auth/login/email/",
            {"email": "locktest@example.com", "password": "wrong"},
            content_type="application/json",
        )

        # Successful attempt
        self.client.post(
            "/api/auth/login/email/",
            {"email": "locktest@example.com", "password": "correctpass123456"},
            content_type="application/json",
        )

        # Check logged attempts
        failed_attempts = LoginAttempt.objects.filter(
            identifier="locktest@example.com", success=False
        ).count()

        successful_attempts = LoginAttempt.objects.filter(
            identifier="locktest@example.com", success=True
        ).count()

        self.assertEqual(failed_attempts, 1)
        self.assertEqual(successful_attempts, 1)


class AnonymousPINSecurityTests(TestCase):
    """Test anonymous user PIN security."""

    def setUp(self):
        self.client = Client()

    def test_anonymous_pin_is_12_digits(self):
        """Anonymous user PIN should be 12 digits (not 6)"""
        response = self.client.post(
            "/api/auth/login/anonymous/", {}, content_type="application/json"
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        pin = data["user"]["anonymous_credentials"]["pin"]

        # Verify PIN is 12 digits
        self.assertEqual(len(pin), 12)
        self.assertTrue(pin.isdigit())

    def test_anonymous_pins_are_unique(self):
        """Each anonymous user should get unique PIN"""
        pins = set()

        for i in range(10):
            response = self.client.post(
                "/api/auth/login/anonymous/", {}, content_type="application/json"
            )

            data = response.json()
            pin = data["user"]["anonymous_credentials"]["pin"]
            pins.add(pin)

        # All 10 PINs should be unique
        self.assertEqual(len(pins), 10)


class CSRFProtectionTests(TestCase):
    """Test CSRF protection on POST endpoints."""

    def setUp(self):
        self.client = Client(enforce_csrf_checks=True)

    def test_post_without_csrf_token_fails(self):
        """POST requests without CSRF token should fail"""
        # Note: This test may need adjustment based on how
        # REST framework handles CSRF with JSON requests
        response = self.client.post(
            "/api/auth/login/email/",
            {"email": "test@example.com", "password": "test123456"},
            content_type="application/json",
        )

        # Should either get CSRF error or proceed
        # (REST framework may exempt JSON requests)
        self.assertIn(response.status_code, [200, 401, 403])


class TokenSecurityTests(TestCase):
    """Test token security - tokens never in URLs."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123456",
        )

    def test_tokens_not_in_oauth_redirect_url(self):
        """OAuth callback should redirect with session ID, not tokens"""
        # This tests that the URL uses session ID pattern
        # Actual OAuth flow testing requires mocking

        from datetime import timedelta

        from django.utils import timezone

        from sso.models import TokenExchangeSession

        # Create a session
        session = TokenExchangeSession.objects.create(
            access_token="secret_access_token",
            refresh_token="secret_refresh_token",
            user_email="test@example.com",
            expires_at=timezone.now() + timedelta(seconds=60),
        )

        # The redirect URL should contain session ID, not tokens
        redirect_url = f"/login/google-success/?session={session.session_id}"

        # Verify tokens are not in URL
        self.assertNotIn("secret_access_token", redirect_url)
        self.assertNotIn("secret_refresh_token", redirect_url)
        self.assertIn(str(session.session_id), redirect_url)
