"""
Unit tests for sso.middleware.OAuthAdminMiddleware

Tests OAuth admin authentication middleware.
"""

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from django.test import RequestFactory, TestCase, override_settings

from sso.middleware import OAuthAdminMiddleware

User = get_user_model()


class OAuthAdminMiddlewareTests(TestCase):
    """Test OAuthAdminMiddleware functionality."""

    def setUp(self):
        """Create test fixtures."""
        self.factory = RequestFactory()
        self.middleware = OAuthAdminMiddleware(
            get_response=lambda r: MagicMock(status_code=200)
        )

    def _add_session_to_request(self, request):
        """Add session support to request."""
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)
        request.session.save()

    def test_non_admin_request_passes_through(self):
        """Test non-admin URLs are not processed by middleware."""
        request = self.factory.get("/dashboard/")
        self._add_session_to_request(request)
        request.user = MagicMock(is_authenticated=False)

        response = self.middleware(request)

        # Should pass through without processing
        self.assertEqual(response.status_code, 200)

    def test_admin_request_detected(self):
        """Test admin URLs are correctly detected."""
        request = self.factory.get("/admin/")

        result = self.middleware._is_admin_request(request)

        self.assertTrue(result)

    def test_admin_login_request_detected(self):
        """Test admin login URL is detected as admin request."""
        request = self.factory.get("/admin/login/")

        result = self.middleware._is_admin_request(request)

        self.assertTrue(result)

    def test_non_admin_request_not_detected(self):
        """Test non-admin URLs are not detected as admin."""
        request = self.factory.get("/dashboard/")

        result = self.middleware._is_admin_request(request)

        self.assertFalse(result)

    def test_api_request_not_detected_as_admin(self):
        """Test API URLs are not detected as admin."""
        request = self.factory.get("/api/users/")

        result = self.middleware._is_admin_request(request)

        self.assertFalse(result)

    def test_authenticated_user_passes_through(self):
        """Test already authenticated users pass through."""
        user = User.objects.create(
            email="test@example.com",
            username="test",
            is_staff=True,
        )

        request = self.factory.get("/admin/")
        self._add_session_to_request(request)
        request.user = user

        response = self.middleware(request)

        # Should pass through without additional OAuth processing
        self.assertEqual(response.status_code, 200)

    def test_get_oauth_token_from_authorization_header(self):
        """Test OAuth token extraction from Authorization header."""
        request = self.factory.get(
            "/admin/", HTTP_AUTHORIZATION="Bearer test-oauth-token-123"
        )
        self._add_session_to_request(request)

        token = self.middleware._get_oauth_token(request)

        self.assertEqual(token, "test-oauth-token-123")

    def test_get_oauth_token_from_session(self):
        """Test OAuth token extraction from session."""
        request = self.factory.get("/admin/")
        self._add_session_to_request(request)
        request.session["oauth_token"] = "session-oauth-token-456"

        token = self.middleware._get_oauth_token(request)

        self.assertEqual(token, "session-oauth-token-456")

    def test_authorization_header_takes_precedence(self):
        """Test Authorization header takes precedence over session."""
        request = self.factory.get("/admin/", HTTP_AUTHORIZATION="Bearer header-token")
        self._add_session_to_request(request)
        request.session["oauth_token"] = "session-token"

        token = self.middleware._get_oauth_token(request)

        # Header token should be returned
        self.assertEqual(token, "header-token")

    def test_no_oauth_token_returns_none(self):
        """Test returns None when no OAuth token present."""
        request = self.factory.get("/admin/")
        self._add_session_to_request(request)

        token = self.middleware._get_oauth_token(request)

        self.assertIsNone(token)

    def test_invalid_authorization_header_format(self):
        """Test invalid Authorization header format returns None."""
        request = self.factory.get("/admin/", HTTP_AUTHORIZATION="InvalidFormat token")
        self._add_session_to_request(request)

        token = self.middleware._get_oauth_token(request)

        self.assertIsNone(token)

    @patch("sso.middleware.login")
    @patch("sso.middleware.authenticate")
    def test_authenticate_with_valid_oauth_token(self, mock_authenticate, mock_login):
        """Test successful authentication with valid OAuth token."""
        # Create user
        user = User.objects.create(
            email="test@example.com",
            username="test",
            is_staff=True,
        )

        # Mock successful authentication
        mock_authenticate.return_value = user

        request = self.factory.get("/admin/")
        self._add_session_to_request(request)

        result = self.middleware._authenticate_with_oauth(request, "valid-token")

        self.assertIsNotNone(result)
        self.assertEqual(result.email, "test@example.com")
        mock_authenticate.assert_called_once_with(request, oauth_token="valid-token")
        mock_login.assert_called_once_with(
            request, user, backend="sso.backends.OAuthBackend"
        )

    @patch("sso.middleware.authenticate")
    def test_authenticate_with_invalid_oauth_token(self, mock_authenticate):
        """Test authentication fails with invalid OAuth token."""
        # Mock failed authentication
        mock_authenticate.return_value = None

        request = self.factory.get("/admin/")
        self._add_session_to_request(request)

        result = self.middleware._authenticate_with_oauth(request, "invalid-token")

        self.assertIsNone(result)
        mock_authenticate.assert_called_once_with(request, oauth_token="invalid-token")

    @patch("sso.middleware.login")
    @patch("sso.middleware.authenticate")
    def test_oauth_token_cleared_from_session_after_authentication(
        self, mock_authenticate, mock_login
    ):
        """Test OAuth token is cleared from session after successful authentication."""
        # Create user
        user = User.objects.create(
            email="test@example.com",
            username="test",
            is_staff=True,
        )

        # Mock successful authentication
        mock_authenticate.return_value = user

        request = self.factory.get("/admin/")
        self._add_session_to_request(request)
        request.session["oauth_token"] = "test-token"

        result = self.middleware._authenticate_with_oauth(request, "test-token")

        self.assertIsNotNone(result)
        # Token should be cleared from session
        self.assertNotIn("oauth_token", request.session)

    @patch("sso.middleware.authenticate")
    def test_authenticate_exception_handled_gracefully(self, mock_authenticate):
        """Test exceptions during authentication are handled gracefully."""
        # Mock exception
        mock_authenticate.side_effect = Exception("Unexpected error")

        request = self.factory.get("/admin/")
        self._add_session_to_request(request)

        result = self.middleware._authenticate_with_oauth(request, "problematic-token")

        self.assertIsNone(result)

    @patch("sso.middleware.authenticate")
    def test_admin_request_without_token_passes_through(self, mock_authenticate):
        """Test admin request without OAuth token passes through to Django admin."""
        request = self.factory.get("/admin/")
        self._add_session_to_request(request)
        request.user = MagicMock(is_authenticated=False)

        response = self.middleware(request)

        # Should not attempt OAuth authentication
        mock_authenticate.assert_not_called()
        # Should pass through (Django admin will handle login)
        self.assertEqual(response.status_code, 200)

    @patch("sso.middleware.login")
    @patch("sso.middleware.authenticate")
    def test_full_oauth_flow_with_authorization_header(
        self, mock_authenticate, mock_login
    ):
        """Test complete OAuth flow with Authorization header."""
        # Create user
        user = User.objects.create(
            email="admin@example.com",
            username="admin",
            is_staff=True,
            is_superuser=True,
        )

        # Mock successful authentication
        mock_authenticate.return_value = user

        request = self.factory.get(
            "/admin/", HTTP_AUTHORIZATION="Bearer valid-oauth-token"
        )
        self._add_session_to_request(request)
        request.user = MagicMock(is_authenticated=False)

        response = self.middleware(request)

        # Should authenticate via OAuth
        mock_authenticate.assert_called_once_with(
            request, oauth_token="valid-oauth-token"
        )
        mock_login.assert_called_once()
        self.assertEqual(response.status_code, 200)

    @patch("sso.middleware.login")
    @patch("sso.middleware.authenticate")
    def test_full_oauth_flow_with_session_token(self, mock_authenticate, mock_login):
        """Test complete OAuth flow with session token."""
        # Create user
        user = User.objects.create(
            email="admin@example.com",
            username="admin",
            is_staff=True,
        )

        # Mock successful authentication
        mock_authenticate.return_value = user

        request = self.factory.get("/admin/")
        self._add_session_to_request(request)
        request.session["oauth_token"] = "session-oauth-token"
        request.user = MagicMock(is_authenticated=False)

        response = self.middleware(request)

        # Should authenticate via OAuth
        mock_authenticate.assert_called_once_with(
            request, oauth_token="session-oauth-token"
        )
        mock_login.assert_called_once()
        # Token should be cleared from session
        self.assertNotIn("oauth_token", request.session)
        self.assertEqual(response.status_code, 200)

    @patch("sso.middleware.authenticate")
    def test_failed_oauth_authentication_continues_request(self, mock_authenticate):
        """Test failed OAuth authentication allows request to continue."""
        # Mock failed authentication
        mock_authenticate.return_value = None

        request = self.factory.get("/admin/", HTTP_AUTHORIZATION="Bearer invalid-token")
        self._add_session_to_request(request)
        request.user = MagicMock(is_authenticated=False)

        response = self.middleware(request)

        # Should still return response (Django admin will handle login redirect)
        self.assertEqual(response.status_code, 200)

    def test_middleware_does_not_block_password_auth(self):
        """Test middleware does not interfere with password-based authentication."""
        # Create authenticated user (already logged in via password)
        user = User.objects.create(
            email="password@example.com",
            username="password",
            is_staff=True,
        )

        request = self.factory.get("/admin/")
        self._add_session_to_request(request)
        request.user = user  # Already authenticated

        response = self.middleware(request)

        # Should pass through without OAuth processing
        self.assertEqual(response.status_code, 200)


class OAuthAdminMiddlewareIntegrationTests(TestCase):
    """Integration tests for OAuthAdminMiddleware."""

    @override_settings(
        ADMIN_WHITELIST="admin@barge2rail.com",
        SUPERUSER_WHITELIST="admin@barge2rail.com",
    )
    @patch("sso.middleware.authenticate")
    def test_end_to_end_admin_oauth_authentication(self, mock_authenticate):
        """Test complete end-to-end OAuth authentication for admin."""
        # Create user with admin permissions
        user = User.objects.create(
            email="admin@barge2rail.com",
            username="admin",
            is_staff=True,
            is_superuser=True,
        )

        # Mock authentication to return user
        mock_authenticate.return_value = user

        factory = RequestFactory()
        middleware = OAuthAdminMiddleware(
            get_response=lambda r: MagicMock(status_code=200)
        )

        request = factory.get("/admin/", HTTP_AUTHORIZATION="Bearer valid-oauth-token")
        session_middleware = SessionMiddleware(lambda x: x)
        session_middleware.process_request(request)
        request.session.save()
        request.user = MagicMock(is_authenticated=False)

        response = middleware(request)

        # Authentication should succeed
        mock_authenticate.assert_called_once()
        self.assertEqual(response.status_code, 200)

    @patch("sso.middleware.authenticate")
    def test_non_admin_user_oauth_token_handled(self, mock_authenticate):
        """Test OAuth token from non-admin user is handled."""
        # Create user without admin permissions
        user = User.objects.create(
            email="user@example.com",
            username="user",
            is_staff=False,
            is_superuser=False,
        )

        # Mock authentication to return non-admin user
        mock_authenticate.return_value = user

        factory = RequestFactory()
        middleware = OAuthAdminMiddleware(
            get_response=lambda r: MagicMock(status_code=200)
        )

        request = factory.get("/admin/", HTTP_AUTHORIZATION="Bearer non-admin-token")
        session_middleware = SessionMiddleware(lambda x: x)
        session_middleware.process_request(request)
        request.session.save()
        request.user = MagicMock(is_authenticated=False)

        response = middleware(request)

        # Authentication happens, but Django admin will check is_staff
        mock_authenticate.assert_called_once()
        self.assertEqual(response.status_code, 200)
