"""
OAuth Redirect URI Tests
Tests to verify redirect URI configuration is correct and consistent.
Added: October 28, 2025 - Bug fix for redirect_uri_mismatch
"""

from unittest.mock import MagicMock, patch

from django.conf import settings
from django.test import Client, TestCase, override_settings
from django.urls import reverse


class OAuthRedirectURITests(TestCase):
    """Test OAuth redirect URI configuration and consistency."""

    def setUp(self):
        self.client = Client()

    def test_redirect_uri_format(self):
        """Verify redirect URI has correct format with trailing slash."""
        response = self.client.get("/auth/login/google/", follow=False)

        # Should redirect to Google OAuth
        self.assertEqual(response.status_code, 302)

        # Extract redirect_uri parameter from Location header
        location = response.url
        self.assertIn("redirect_uri=", location)

        # Verify redirect_uri ends with /auth/google/callback/
        import urllib.parse

        params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        redirect_uri = params.get("redirect_uri", [""])[0]

        self.assertTrue(
            redirect_uri.endswith("/auth/google/callback/"),
            f"Redirect URI must end with /auth/google/callback/ but got: {redirect_uri}",
        )

    @override_settings(BASE_URL="https://sso.barge2rail.com")
    def test_redirect_uri_production_format(self):
        """Verify production redirect URI format."""
        # Simulate production request
        response = self.client.get(
            "/auth/login/google/",
            headers={"host": "sso.barge2rail.com"},
            secure=True,
            follow=False,
        )

        self.assertEqual(response.status_code, 302)

        # Extract and verify redirect_uri
        import urllib.parse

        location = response.url
        params = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
        redirect_uri = params.get("redirect_uri", [""])[0]

        self.assertEqual(
            redirect_uri,
            "https://sso.barge2rail.com/auth/google/callback/",
            "Production redirect URI must match exactly",
        )

    def test_redirect_uri_consistency_across_endpoints(self):
        """Verify redirect URI is same across all OAuth endpoints."""
        # Test auth_views endpoint
        response1 = self.client.get("/auth/login/google/", follow=False)

        # Test oauth_views endpoint (if different route exists)
        try:
            response2 = self.client.get("/api/auth/login/google/", follow=False)
        except Exception:
            # If route doesn't exist, that's okay - skip this check
            response2 = None

        if response1.status_code == 302:
            import urllib.parse

            params1 = urllib.parse.parse_qs(urllib.parse.urlparse(response1.url).query)
            redirect_uri1 = params1.get("redirect_uri", [""])[0]

            # Should NOT have /api prefix
            self.assertNotIn("/api/auth/google/callback", redirect_uri1)
            self.assertIn("/auth/google/callback/", redirect_uri1)

        if response2 and response2.status_code == 302:
            import urllib.parse

            params2 = urllib.parse.parse_qs(urllib.parse.urlparse(response2.url).query)
            redirect_uri2 = params2.get("redirect_uri", [""])[0]

            # Both should match
            self.assertEqual(
                redirect_uri1,
                redirect_uri2,
                "Redirect URIs must be consistent across all endpoints",
            )


class OAuthCallbackErrorHandlingTests(TestCase):
    """Test OAuth callback error handling improvements."""

    def setUp(self):
        self.client = Client()

    def test_callback_missing_state(self):
        """OAuth callback without state parameter should return clear error."""
        response = self.client.get("/auth/google/callback/?code=test_code")

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)
        self.assertIn("session", data["error"].lower())

    def test_callback_missing_code(self):
        """OAuth callback without code parameter should return clear error."""
        # Set up session state
        session = self.client.session
        session["oauth_state"] = "test_state_12345"
        session.save()

        response = self.client.get("/auth/google/callback/?state=test_state_12345")

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)
        self.assertIn("code", data["error"].lower())

    def test_callback_state_mismatch(self):
        """OAuth callback with mismatched state should fail."""
        # Set up session state
        session = self.client.session
        session["oauth_state"] = "correct_state"
        session.save()

        # Send different state in callback
        response = self.client.get(
            "/auth/google/callback/?code=test_code&state=wrong_state"
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)
        self.assertIn("state", data["error"].lower())

    @patch("requests.post")
    def test_callback_network_timeout(self, mock_post):
        """OAuth callback should handle network timeouts gracefully."""
        import requests

        # Mock timeout exception
        mock_post.side_effect = requests.Timeout("Connection timeout")

        # Set up valid session state
        session = self.client.session
        session["oauth_state"] = "test_state"
        session.save()

        response = self.client.get(
            "/auth/google/callback/?code=test_code&state=test_state"
        )

        self.assertEqual(response.status_code, 503)
        data = response.json()
        self.assertIn("error", data)
        # Should NOT expose internal error details
        self.assertNotIn("timeout", data["error"].lower())
        self.assertIn("unavailable", data["error"].lower())

    @patch("requests.post")
    def test_callback_google_api_error(self, mock_post):
        """OAuth callback should handle Google API errors gracefully."""
        import requests

        # Mock HTTP error from Google
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "invalid_grant"
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            response=mock_response
        )
        mock_post.return_value = mock_response

        # Set up valid session state
        session = self.client.session
        session["oauth_state"] = "test_state"
        session.save()

        response = self.client.get(
            "/auth/google/callback/?code=invalid_code&state=test_state"
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)
        # Should NOT expose Google's error details to user
        self.assertNotIn("invalid_grant", data["error"])


class OAuthSecurityTests(TestCase):
    """Test OAuth security measures."""

    def setUp(self):
        self.client = Client()

    def test_state_parameter_required(self):
        """State parameter must be present in OAuth flow."""
        response = self.client.get("/auth/login/google/", follow=False)

        self.assertEqual(response.status_code, 302)

        # Extract state from redirect URL
        import urllib.parse

        params = urllib.parse.parse_qs(urllib.parse.urlparse(response.url).query)
        state = params.get("state", [""])[0]

        self.assertIsNotNone(state)
        self.assertGreater(len(state), 20, "State should be substantial random token")

    def test_state_stored_in_session(self):
        """OAuth state must be stored in session for verification."""
        response = self.client.get("/auth/login/google/", follow=False)

        self.assertEqual(response.status_code, 302)

        # Verify state is in session
        self.assertIn("oauth_state", self.client.session)
        stored_state = self.client.session["oauth_state"]

        # Verify state in URL matches session
        import urllib.parse

        params = urllib.parse.parse_qs(urllib.parse.urlparse(response.url).query)
        url_state = params.get("state", [""])[0]

        self.assertEqual(stored_state, url_state)

    def test_csrf_protection_via_state(self):
        """State parameter provides CSRF protection."""
        # Attacker tries to inject malicious state
        malicious_state = "attacker_controlled_state"

        response = self.client.get(
            f"/auth/google/callback/?code=malicious_code&state={malicious_state}"
        )

        # Should fail because state not in session
        self.assertEqual(response.status_code, 400)


class OAuthIntegrationTests(TestCase):
    """Integration tests for complete OAuth flow."""

    def setUp(self):
        self.client = Client()

    @patch("sso.oauth_views.requests.post")
    @patch("sso.oauth_views.id_token.verify_oauth2_token")
    def test_complete_oauth_flow_success(self, mock_verify, mock_post):
        """Test complete OAuth flow from initiation to callback."""
        # Step 1: Initiate OAuth flow
        response = self.client.get("/auth/login/google/", follow=False)
        self.assertEqual(response.status_code, 302)

        # Extract state from redirect
        import urllib.parse

        params = urllib.parse.parse_qs(urllib.parse.urlparse(response.url).query)
        state = params.get("state", [""])[0]
        redirect_uri = params.get("redirect_uri", [""])[0]

        # Verify redirect URI format
        self.assertTrue(redirect_uri.endswith("/auth/google/callback/"))

        # Step 2: Mock Google's token response
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            "access_token": "google_access_token",
            "id_token": "google_id_token",
            "refresh_token": "google_refresh_token",
        }
        mock_post.return_value = mock_token_response

        # Step 3: Mock ID token verification
        mock_verify.return_value = {
            "sub": "google_user_123",
            "email": "test@barge2rail.com",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
        }

        # Step 4: Simulate Google callback
        callback_response = self.client.get(
            f"/auth/google/callback/?code=auth_code_123&state={state}"
        )

        # Should redirect to success page
        self.assertEqual(callback_response.status_code, 302)
        self.assertIn("google-success", callback_response.url)


class OAuthLoggingTests(TestCase):
    """Test OAuth logging for debugging and security audit."""

    def setUp(self):
        self.client = Client()

    @patch("sso.oauth_views.logger")
    def test_oauth_initiation_logged(self, mock_logger):
        """OAuth flow initiation should be logged."""
        self.client.get("/auth/login/google/")

        # Verify logging occurred
        mock_logger.info.assert_called()

        # Verify log message contains relevant info
        calls = [str(call) for call in mock_logger.info.call_args_list]
        log_messages = " ".join(calls)
        self.assertIn("GOOGLE LOGIN", log_messages.upper())

    @patch("sso.oauth_views.logger")
    def test_oauth_callback_errors_logged(self, mock_logger):
        """OAuth callback errors should be logged with context."""
        # Trigger error: missing state
        self.client.get("/auth/google/callback/?code=test")

        # Verify error was logged
        mock_logger.error.assert_called()

        # Verify log contains useful context
        calls = [str(call) for call in mock_logger.error.call_args_list]
        log_messages = " ".join(calls)
        self.assertIn("state", log_messages.lower())
