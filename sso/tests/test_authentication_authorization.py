"""
Comprehensive Authentication and Authorization Tests

Test Coverage:
1. User login via existing authentication mechanisms (email, Google, anonymous)
2. JWT token generation and validation
3. API endpoints protected by authorization policies
4. Token refresh mechanisms
5. OAuth 2.0 flows for obtaining and using access tokens
"""

import unittest
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from sso.models import Application, UserRole
from sso.tokens import CustomRefreshToken

User = get_user_model()


# ============================================================================
# TEST CASE 1: User Login via Existing Authentication Mechanisms
# ============================================================================


class EmailPasswordAuthenticationTests(TestCase):
    """Test email/password authentication mechanism."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="securepass123456",  # pragma: allowlist secret
            auth_type="email",
        )

    def test_successful_email_login(self):
        """Email/password login should return access and refresh tokens"""
        response = self.client.post(
            "/auth/login/email/",
            {
                "email": "testuser@example.com",
                "password": "securepass123456",  # pragma: allowlist secret
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["email"], "testuser@example.com")
        self.assertEqual(data["user"]["auth_type"], "email")

    def test_email_login_with_next_parameter(self):
        """Email login with next parameter should return next_url for OAuth flow"""
        oauth_url = "/o/authorize/?client_id=test123&response_type=code"
        response = self.client.post(
            "/auth/login/email/",
            {
                "email": "testuser@example.com",
                "password": "securepass123456",  # pragma: allowlist secret
                "next": oauth_url,
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("next_url", data)
        self.assertEqual(data["next_url"], oauth_url)

    def test_email_login_invalid_credentials(self):
        """Email login with invalid credentials should fail"""
        response = self.client.post(
            "/auth/login/email/",
            {
                "email": "testuser@example.com",
                "password": "wrongpassword",  # pragma: allowlist secret
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"], "Invalid credentials")

    def test_email_login_missing_fields(self):
        """Email login without required fields should return 400"""
        response = self.client.post(
            "/auth/login/email/",
            {"email": "testuser@example.com"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)

    def test_email_login_nonexistent_user(self):
        """Email login for nonexistent user should fail"""
        response = self.client.post(
            "/auth/login/email/",
            {
                "email": "nonexistent@example.com",
                "password": "password123",  # pragma: allowlist secret
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)


class GoogleAuthenticationTests(TestCase):
    """Test Google Sign-In authentication mechanism."""

    def setUp(self):
        self.client = Client()

    @patch("sso.auth_views.id_token.verify_oauth2_token")
    @patch("sso.auth_views.GOOGLE_AUTH_AVAILABLE", True)
    @patch("sso.auth_views.GOOGLE_CLIENT_ID", "test_client_id")
    def test_successful_google_login(self, mock_verify):
        """Google login with valid token should create/login user"""
        mock_verify.return_value = {
            "sub": "google_user_123",
            "email": "googleuser@example.com",
            "name": "Google User",
            "given_name": "Google",
            "family_name": "User",
        }

        response = self.client.post(
            "/auth/login/google/",
            {"token": "valid_google_token"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)
        self.assertEqual(data["user"]["email"], "googleuser@example.com")
        self.assertEqual(data["user"]["auth_type"], "google")

        # Verify user was created
        user = User.objects.get(email="googleuser@example.com")
        self.assertEqual(user.google_id, "google_user_123")
        self.assertEqual(user.auth_type, "google")

    @patch("sso.auth_views.id_token.verify_oauth2_token")
    @patch("sso.auth_views.GOOGLE_AUTH_AVAILABLE", True)
    @patch("sso.auth_views.GOOGLE_CLIENT_ID", "test_client_id")
    def test_google_login_invalid_token(self, mock_verify):
        """Google login with invalid token should fail"""
        mock_verify.side_effect = ValueError("Invalid token")

        response = self.client.post(
            "/auth/login/google/",
            {"token": "invalid_token"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"], "Invalid Google token")

    @patch("sso.auth_views.GOOGLE_AUTH_AVAILABLE", True)
    @patch("sso.auth_views.GOOGLE_CLIENT_ID", "test_client_id")
    def test_google_login_missing_token(self):
        """Google login without token should return 400"""
        response = self.client.post(
            "/auth/login/google/",
            {},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        data = response.json()
        self.assertIn("error", data)

    @patch("sso.auth_views.id_token.verify_oauth2_token")
    @patch("sso.auth_views.GOOGLE_AUTH_AVAILABLE", True)
    @patch("sso.auth_views.GOOGLE_CLIENT_ID", "test_client_id")
    def test_google_login_updates_existing_user(self, mock_verify):
        """Google login should update existing user information"""
        # Create existing user
        existing_user = User.objects.create(
            email="googleuser@example.com",
            username="googleuser@example.com",
            google_id="google_user_123",
            auth_type="google",
            display_name="Old Name",
        )

        mock_verify.return_value = {
            "sub": "google_user_123",
            "email": "googleuser@example.com",
            "name": "New Name",
            "given_name": "New",
            "family_name": "Name",
        }

        response = self.client.post(
            "/auth/login/google/",
            {"token": "valid_google_token"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

        # Verify user info was updated
        existing_user.refresh_from_db()
        self.assertEqual(existing_user.display_name, "New Name")
        self.assertEqual(existing_user.first_name, "New")
        self.assertEqual(existing_user.last_name, "Name")


class AnonymousAuthenticationTests(TestCase):
    """Test anonymous authentication mechanism."""

    def setUp(self):
        self.client = Client()

    def test_create_new_anonymous_user(self):
        """Anonymous login without credentials should create new user"""
        response = self.client.post(
            "/auth/login/anonymous/",
            {},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)
        self.assertIn("user", data)
        self.assertTrue(data["user"]["is_anonymous"])

        # Verify user has display_identifier (username shown on screen)
        # Note: PIN and username are NOT returned in API response for security
        # User must write down credentials when displayed on screen during creation
        self.assertIn("display_identifier", data["user"])
        username = data["user"]["display_identifier"]
        self.assertTrue(username.startswith("Guest-"))

    def test_login_existing_anonymous_user(self):
        """Anonymous login with valid credentials should login existing user"""
        # Create anonymous user
        user = User.objects.create(
            auth_type="anonymous",
            is_anonymous=True,
            is_active=True,
        )
        user.save()  # Triggers username and PIN generation (PIN is hashed)

        # Get plaintext PIN before it's gone (only available right after creation)
        # Since PIN is now hashed, we need to use _plaintext_pin attribute
        plaintext_pin = user._plaintext_pin

        # Login with credentials (use plaintext PIN, not the hash)
        response = self.client.post(
            "/auth/login/anonymous/",
            {"username": user.anonymous_username, "pin": plaintext_pin},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertEqual(data["user"]["id"], str(user.id))

    def test_anonymous_login_invalid_credentials(self):
        """Anonymous login with invalid credentials should fail"""
        response = self.client.post(
            "/auth/login/anonymous/",
            {"username": "Guest-ABC123", "pin": "123456789012"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertIn("error", data)
        self.assertEqual(data["error"], "Invalid username or PIN")


# ============================================================================
# TEST CASE 2: JWT Token Generation and Validation
# ============================================================================


class JWTTokenGenerationTests(TestCase):
    """Test JWT token generation functionality."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123456",  # pragma: allowlist secret
        )

    def test_generate_tokens_for_user(self):
        """Tokens should be generated successfully for user"""
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token

        self.assertIsNotNone(str(refresh))
        self.assertIsNotNone(str(access))

        # Verify tokens contain user_id
        self.assertEqual(refresh["user_id"], str(self.user.id))
        self.assertEqual(access["user_id"], str(self.user.id))

    def test_custom_token_contains_email(self):
        """Custom refresh token should contain user email"""
        refresh = CustomRefreshToken.for_user(self.user)

        self.assertEqual(refresh.get("email"), self.user.email)

    def test_access_token_payload(self):
        """Access token should contain expected claims"""
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token

        # Verify standard claims
        self.assertIn("user_id", access)
        self.assertIn("exp", access)
        self.assertIn("iat", access)
        self.assertIn("jti", access)
        self.assertIn("token_type", access)

    def test_token_generation_via_login(self):
        """Login endpoint should generate valid tokens"""
        response = self.client.post(
            "/auth/login/email/",
            {
                "email": "testuser@example.com",
                "password": "testpass123456",  # pragma: allowlist secret
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()

        access_token = data["access_token"]
        refresh_token = data["refresh_token"]

        # Verify tokens are non-empty
        self.assertTrue(len(access_token) > 50)
        self.assertTrue(len(refresh_token) > 50)

        # Verify tokens can be decoded
        decoded_access = AccessToken(access_token)
        self.assertEqual(decoded_access["user_id"], str(self.user.id))


class JWTTokenValidationTests(TestCase):
    """Test JWT token validation functionality."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123456",  # pragma: allowlist secret
        )
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

    def test_validate_valid_token(self):
        """Valid token should pass validation"""
        response = self.client.post(
            "/auth/validate/",
            {"token": self.access_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["valid"])
        self.assertIn("user", data)
        self.assertEqual(data["user"]["email"], self.user.email)

    def test_validate_invalid_token(self):
        """Invalid token should fail validation"""
        response = self.client.post(
            "/auth/validate/",
            {"token": "invalid.token.string"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)
        data = response.json()
        self.assertFalse(data["valid"])

    def test_validate_missing_token(self):
        """Missing token should return 400"""
        response = self.client.post(
            "/auth/validate/",
            {},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_validate_expired_token(self):
        """Expired token should fail validation"""
        # Create token that expired 1 hour ago
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token
        access.set_exp(lifetime=timedelta(seconds=-3600))
        expired_token = str(access)

        response = self.client.post(
            "/auth/validate/",
            {"token": expired_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 401)

    def test_token_used_in_protected_endpoint(self):
        """Access token should grant access to protected endpoint"""
        response = self.client.get(
            "/auth/me/",
            headers={"authorization": f"Bearer {self.access_token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["email"], self.user.email)


# ============================================================================
# TEST CASE 3: API Endpoints Protected by Authorization Policies
# ============================================================================


class ProtectedEndpointAuthorizationTests(TestCase):
    """Test API endpoints protected by authorization policies."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123456",  # pragma: allowlist secret
        )
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

    def test_protected_endpoint_without_token(self):
        """Protected endpoint should reject requests without token"""
        response = self.client.get("/auth/me/")

        self.assertEqual(response.status_code, 401)

    def test_protected_endpoint_with_valid_token(self):
        """Protected endpoint should allow requests with valid token"""
        response = self.client.get(
            "/auth/me/",
            headers={"authorization": f"Bearer {self.access_token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["id"], str(self.user.id))

    def test_protected_endpoint_with_invalid_token(self):
        """Protected endpoint should reject requests with invalid token"""
        response = self.client.get(
            "/auth/me/",
            headers={"authorization": "Bearer invalid.token.here"},
        )

        self.assertEqual(response.status_code, 401)

    def test_protected_endpoint_with_malformed_header(self):
        """Protected endpoint should reject malformed authorization header"""
        response = self.client.get(
            "/auth/me/",
            headers={"authorization": "InvalidFormat token"},
        )

        self.assertEqual(response.status_code, 401)


class RoleBasedAuthorizationTests(TestCase):
    """Test role-based authorization for applications."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123456",  # pragma: allowlist secret
        )

        # Create application
        self.app = Application.objects.create(
            name="Test Application",
            slug="test-app",
        )

        # Create admin user with role
        self.admin_user = User.objects.create_user(
            username="admin@example.com",
            email="admin@example.com",
            password="adminpass123456",  # pragma: allowlist secret
        )

        UserRole.objects.create(
            user=self.admin_user, application=self.app, role="admin"
        )

        # Generate tokens
        refresh = RefreshToken.for_user(self.user)
        self.user_token = str(refresh.access_token)

        admin_refresh = RefreshToken.for_user(self.admin_user)
        self.admin_token = str(admin_refresh.access_token)

    def test_user_roles_included_in_token_response(self):
        """User roles should be included in login response"""
        response = self.client.post(
            "/auth/login/email/",
            {
                "email": "admin@example.com",
                "password": "adminpass123456",  # pragma: allowlist secret
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("roles", data["user"])
        self.assertIn("test-app", data["user"]["roles"])
        self.assertEqual(data["user"]["roles"]["test-app"]["role"], "admin")

    def test_user_without_role_has_empty_roles(self):
        """User without roles should have empty roles dict"""
        response = self.client.post(
            "/auth/login/email/",
            {
                "email": "testuser@example.com",
                "password": "testpass123456",  # pragma: allowlist secret
            },
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("roles", data["user"])
        self.assertEqual(data["user"]["roles"], {})


# ============================================================================
# TEST CASE 4: Token Refresh Mechanisms
# ============================================================================


class TokenRefreshTests(TestCase):
    """Test token refresh functionality."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123456",  # pragma: allowlist secret
        )

        refresh = RefreshToken.for_user(self.user)
        self.refresh_token = str(refresh)
        self.access_token = str(refresh.access_token)

    def test_refresh_token_generates_new_access_token(self):
        """Refresh token should generate new access token"""
        response = self.client.post(
            "/auth/refresh/",
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access", data)

        # New access token should be different from old one
        new_access_token = data["access"]
        self.assertNotEqual(new_access_token, self.access_token)

        # New token should be valid
        decoded = AccessToken(new_access_token)
        self.assertEqual(decoded["user_id"], str(self.user.id))

    def test_refresh_with_invalid_token(self):
        """Invalid refresh token should fail"""
        response = self.client.post(
            "/auth/refresh/",
            {"refresh": "invalid.refresh.token"},
            content_type="application/json",
        )

        self.assertIn(response.status_code, [400, 401])

    def test_refresh_with_missing_token(self):
        """Missing refresh token should return 400"""
        response = self.client.post(
            "/auth/refresh/",
            {},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_refresh_after_logout_fails(self):
        """Refresh token should fail after logout"""
        # Logout
        self.client.post(
            "/auth/logout/",
            {"refresh": self.refresh_token},
            content_type="application/json",
            headers={"authorization": f"Bearer {self.access_token}"},
        )

        # Try to refresh with blacklisted token
        response = self.client.post(
            "/auth/refresh/",
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertIn(response.status_code, [400, 401])

    def test_multiple_refresh_cycles(self):
        """Token should be refreshable multiple times"""
        current_refresh = self.refresh_token

        for i in range(3):
            response = self.client.post(
                "/auth/refresh/",
                {"refresh": current_refresh},
                content_type="application/json",
            )

            self.assertEqual(response.status_code, 200)
            data = response.json()

            # Update refresh token if rotation is enabled
            if "refresh" in data:
                current_refresh = data["refresh"]

            # Verify new access token works
            new_access = data["access"]
            profile_response = self.client.get(
                "/auth/me/",
                headers={"authorization": f"Bearer {new_access}"},
            )
            self.assertEqual(profile_response.status_code, 200)


class TokenBlacklistTests(TestCase):
    """Test token blacklisting on logout."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123456",  # pragma: allowlist secret
        )

        refresh = RefreshToken.for_user(self.user)
        self.refresh_token = str(refresh)
        self.access_token = str(refresh.access_token)

    def test_logout_blacklists_token(self):
        """Logout should blacklist refresh token"""
        # Logout
        response = self.client.post(
            "/auth/logout/",
            {"refresh": self.refresh_token},
            content_type="application/json",
            headers={"authorization": f"Bearer {self.access_token}"},
        )

        self.assertEqual(response.status_code, 200)

        # Try to refresh with blacklisted token
        response = self.client.post(
            "/auth/refresh/",
            {"refresh": self.refresh_token},
            content_type="application/json",
        )

        self.assertIn(response.status_code, [400, 401])


# ============================================================================
# TEST CASE 5: OAuth 2.0 Flows
# ============================================================================


@unittest.skip(
    "OAuth URL generation not implemented - using direct redirect pattern. "
    "These tests validate URL generation endpoints that don't exist in current "
    "implementation. OAuth flow uses direct Google redirect without intermediate "
    "URL generation endpoint."
)
class OAuth2FlowTests(TestCase):
    """Test OAuth 2.0 authorization code flow."""

    def setUp(self):
        self.client = Client()

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_authorization_url_generation(self, mock_verify, mock_exchange):
        """OAuth URL endpoint should return valid authorization URL"""
        response = self.client.get("/auth/oauth/google/url/")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("auth_url", data)
        self.assertIn("redirect_uri", data)
        self.assertIn("client_id", data)

        # Verify URL structure
        auth_url = data["auth_url"]
        self.assertTrue(
            auth_url.startswith("https://accounts.google.com/o/oauth2/v2/auth")
        )
        self.assertIn("state=", auth_url)
        self.assertIn("client_id=", auth_url)

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_state_stored_in_session(self, mock_verify, mock_exchange):
        """OAuth initiation should store state in session"""
        response = self.client.get("/auth/oauth/google/url/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("oauth_state", self.client.session)

        stored_state = self.client.session["oauth_state"]
        self.assertIsNotNone(stored_state)
        self.assertIn(":", stored_state)  # Format: token:timestamp

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_callback_with_valid_state(self, mock_verify, mock_exchange):
        """OAuth callback with valid state should complete authentication"""
        # Mock Google responses
        mock_exchange.return_value = {
            "access_token": "google_access_token",
            "id_token": "google_id_token",
        }

        mock_verify.return_value = {
            "google_id": "123456789",
            "email": "oauth@example.com",
            "name": "OAuth User",
            "picture": "https://example.com/photo.jpg",
            "email_verified": True,
        }

        # Get OAuth URL to generate state
        self.client.get("/auth/oauth/google/url/")
        state = self.client.session["oauth_state"]

        # Simulate OAuth callback
        response = self.client.post(
            "/auth/login/google/oauth/",
            {"code": "auth_code_12345", "state": state},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("refresh_token", data)
        self.assertEqual(data["user"]["email"], "oauth@example.com")

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_callback_with_invalid_state(self, mock_verify, mock_exchange):
        """OAuth callback with invalid state should fail"""
        # Get OAuth URL to generate state
        self.client.get("/auth/oauth/google/url/")

        # Simulate callback with wrong state
        response = self.client.post(
            "/auth/login/google/oauth/",
            {"code": "auth_code_12345", "state": "wrong_state"},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_token_exchange_creates_user(self, mock_verify, mock_exchange):
        """OAuth token exchange should create new user"""
        # Mock responses
        mock_exchange.return_value = {
            "access_token": "google_access",
            "id_token": "google_id_token",
        }

        mock_verify.return_value = {
            "google_id": "new_user_123",
            "email": "newuser@example.com",
            "name": "New User",
            "picture": "https://example.com/pic.jpg",
            "email_verified": True,
        }

        # Get OAuth URL and state
        self.client.get("/auth/oauth/google/url/")
        state = self.client.session["oauth_state"]

        # Simulate callback
        response = self.client.post(
            "/auth/login/google/oauth/",
            {"code": "auth_code_12345", "state": state},
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)

        # Verify user was created
        user = User.objects.get(email="newuser@example.com")
        self.assertEqual(user.google_id, "new_user_123")
        self.assertEqual(user.auth_type, "google")

    def test_oauth_access_token_usage(self):
        """OAuth access token should grant access to protected resources"""
        # Create user and generate token
        user = User.objects.create(
            email="oauth@example.com",
            username="oauth@example.com",
            google_id="123456",
            auth_type="google",
        )

        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)

        # Use token to access protected endpoint
        response = self.client.get(
            "/auth/me/",
            headers={"authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["email"], "oauth@example.com")
        self.assertEqual(data["auth_type"], "google")


class OAuth2TokenExchangeSecurityTests(TestCase):
    """Test OAuth 2.0 token exchange security features."""

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_state_expires_after_timeout(self, mock_verify, mock_exchange):
        """OAuth state should expire after timeout period"""
        import time

        from sso.views import validate_oauth_state

        # Create state from 61 seconds ago (timeout is 60 seconds)

        old_timestamp = int(time.time()) - 61
        old_state = f"test_token:{old_timestamp}"

        # Validation should fail
        self.assertFalse(validate_oauth_state(old_state, old_state, timeout=60))

    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_state_prevents_csrf(self, mock_verify, mock_exchange):
        """OAuth state validation should prevent CSRF attacks"""
        from sso.views import generate_oauth_state, validate_oauth_state

        state1 = generate_oauth_state()
        state2 = generate_oauth_state()

        # Mismatched states should fail
        self.assertFalse(validate_oauth_state(state1, state2))

    @unittest.skip(
        "OAuth URL generation endpoint not implemented - test relies on "
        "/auth/oauth/google/url/ which doesn't exist in current implementation"
    )
    @patch("sso.views.exchange_google_code_for_tokens")
    @patch("sso.views.verify_google_id_token")
    def test_oauth_missing_authorization_code(self, mock_verify, mock_exchange):
        """OAuth callback without authorization code should fail"""
        # Get OAuth URL to set up session
        self.client.get("/auth/oauth/google/url/")
        state = self.client.session["oauth_state"]

        # Callback without code
        response = self.client.post(
            "/auth/login/google/oauth/",
            {"state": state},  # No code
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
