"""
Integration Tests
Full end-to-end tests of complete user flows.
"""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase

from sso.models import User

User = get_user_model()


class EmailAuthenticationFlowTests(TestCase):
    """Test complete email/password authentication flow."""

    def setUp(self):
        self.client = Client()

    def test_complete_email_registration_and_login_flow(self):
        """Complete flow: register → login → access protected endpoint → logout"""

        # Step 1: Register
        response = self.client.post(
            "/api/auth/register/email/",
            {
                "email": "newuser@example.com",
                "password": "securepass123456",  # pragma: allowlist secret
                "display_name": "New User",
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]

        # Verify user was created
        user = User.objects.get(email="newuser@example.com")
        self.assertEqual(user.auth_type, "email")

        # Step 2: Access protected endpoint
        response = self.client.get(
            "/api/auth/profile/", headers={"authorization": f"Bearer {access_token}"}
        )

        self.assertEqual(response.status_code, 200)
        profile_data = response.json()
        self.assertEqual(profile_data["email"], "newuser@example.com")

        # Step 3: Logout
        response = self.client.post(
            "/api/auth/logout/",
            {"refresh": refresh_token},
            content_type="application/json",
            headers={"authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(response.status_code, 200)

        # Step 4: Try to use token after logout (should fail)
        response = self.client.post(
            "/api/auth/refresh/",
            {"refresh": refresh_token},
            content_type="application/json",
        )

        self.assertIn(response.status_code, [400, 401])  # Token blacklisted


class AnonymousAuthenticationFlowTests(TestCase):
    """Test complete anonymous authentication flow."""

    def setUp(self):
        self.client = Client()

    def test_complete_anonymous_user_flow(self):
        """Complete flow: create anonymous → login with PIN → logout"""

        # Step 1: Create anonymous user
        response = self.client.post(
            "/api/auth/login/anonymous/", {}, content_type="application/json"
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("user", data)
        username = data["user"]["anonymous_credentials"]["username"]
        pin = data["user"]["anonymous_credentials"]["pin"]

        # Verify PIN is 12 digits
        self.assertEqual(len(pin), 12)

        # Step 2: Logout
        refresh_token = data["refresh_token"]
        access_token = data["access_token"]

        response = self.client.post(
            "/api/auth/logout/",
            {"refresh": refresh_token},
            content_type="application/json",
            headers={"authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(response.status_code, 200)

        # Step 3: Login again with saved credentials
        response = self.client.post(
            "/api/auth/login/anonymous/",
            {"username": username, "pin": pin},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

        # Should get new tokens
        new_data = response.json()
        self.assertIn("access_token", new_data)
        self.assertNotEqual(new_data["access_token"], access_token)


class GoogleOAuthFlowTests(TestCase):
    """Test complete Google OAuth flow (mocked)."""

    def setUp(self):
        self.client = Client()

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_complete_oauth_flow(self, mock_verify, mock_exchange):
        """Complete OAuth flow: URL generation → callback → token exchange"""

        # Mock Google responses
        mock_exchange.return_value = {
            "access_token": "google_access",
            "id_token": "google_id_token",
        }

        mock_verify.return_value = {
            "google_id": "12345",
            "email": "oauth@example.com",
            "name": "OAuth User",
            "picture": "https://example.com/pic.jpg",
            "email_verified": True,
        }

        # Step 1: Get OAuth URL
        response = self.client.get("/api/auth/oauth/google/url/")
        self.assertEqual(response.status_code, 200)

        auth_data = response.json()
        self.assertIn("auth_url", auth_data)

        # Extract state from session
        state = self.client.session["oauth_state"]

        # Step 2: Simulate OAuth callback
        response = self.client.post(
            "/api/auth/login/google/oauth/",
            {"code": "google_auth_code_123", "state": state},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["email"], "oauth@example.com")

        # Verify user was created
        user = User.objects.get(email="oauth@example.com")
        self.assertEqual(user.google_id, "12345")
        self.assertEqual(user.auth_type, "google")


class MultipleUsersIntegrationTests(TestCase):
    """Test system with multiple concurrent users."""

    def setUp(self):
        self.client1 = Client()
        self.client2 = Client()
        self.client3 = Client()

    def test_multiple_users_can_authenticate_simultaneously(self):
        """Multiple users should be able to authenticate at the same time"""

        # Create 3 users
        user1 = User.objects.create_user(
            username="user1@example.com",
            email="user1@example.com",
            password="pass123456",  # pragma: allowlist secret
        )

        user2 = User.objects.create_user(
            username="user2@example.com",
            email="user2@example.com",
            password="pass123456",  # pragma: allowlist secret
        )

        user3 = User.objects.create_user(
            username="user3@example.com",
            email="user3@example.com",
            password="pass123456",  # pragma: allowlist secret
        )

        # All 3 login simultaneously
        response1 = self.client1.post(
            "/api/auth/login/email/",
            # pragma: allowlist secret
            {"email": "user1@example.com", "password": "pass123456"},
            content_type="application/json",
        )

        response2 = self.client2.post(
            "/api/auth/login/email/",
            # pragma: allowlist secret
            {"email": "user2@example.com", "password": "pass123456"},
            content_type="application/json",
        )

        response3 = self.client3.post(
            "/api/auth/login/email/",
            # pragma: allowlist secret
            {"email": "user3@example.com", "password": "pass123456"},
            content_type="application/json",
        )

        # All should succeed
        self.assertEqual(response1.status_code, 200)
        self.assertEqual(response2.status_code, 200)
        self.assertEqual(response3.status_code, 200)

        # All should have different tokens
        token1 = response1.json()["access_token"]
        token2 = response2.json()["access_token"]
        token3 = response3.json()["access_token"]

        self.assertNotEqual(token1, token2)
        self.assertNotEqual(token2, token3)
        self.assertNotEqual(token1, token3)
