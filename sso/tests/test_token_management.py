"""
Token Management Tests
Tests JWT token generation, validation, refresh, and blacklisting.
"""

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from sso.models import User
from sso.tokens import CustomRefreshToken

User = get_user_model()


class TokenGenerationTests(TestCase):
    """Test JWT token generation."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser@example.com',
            email='testuser@example.com',
            password='testpass123456'
        )

    def test_token_generation_for_user(self):
        """Tokens should be generated for authenticated user"""
        refresh = RefreshToken.for_user(self.user)
        access = refresh.access_token

        self.assertIsNotNone(str(refresh))
        self.assertIsNotNone(str(access))

        # Verify token contains user_id
        self.assertEqual(refresh['user_id'], str(self.user.id))
        self.assertEqual(access['user_id'], str(self.user.id))

    def test_token_contains_email(self):
        """Tokens should contain user email"""
        refresh = CustomRefreshToken.for_user(self.user)

        # Check email claim
        self.assertEqual(refresh.get('email'), self.user.email)


class TokenValidationTests(TestCase):
    """Test token validation endpoint."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser@example.com',
            email='testuser@example.com',
            password='testpass123456'
        )

        # Generate valid token
        refresh = RefreshToken.for_user(self.user)
        self.access_token = str(refresh.access_token)

    def test_validate_valid_token(self):
        """Valid token should pass validation"""
        response = self.client.post('/api/auth/validate/', {
            'token': self.access_token
        }, content_type='application/json')

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data['valid'])
        self.assertIn('user', data)
        self.assertEqual(data['user']['email'], self.user.email)

    def test_validate_invalid_token(self):
        """Invalid token should fail validation"""
        response = self.client.post('/api/auth/validate/', {
            'token': 'invalid.token.here'
        }, content_type='application/json')

        self.assertEqual(response.status_code, 401)

        data = response.json()
        self.assertFalse(data['valid'])

    def test_validate_missing_token(self):
        """Missing token should return 400"""
        response = self.client.post('/api/auth/validate/', {
        }, content_type='application/json')

        self.assertEqual(response.status_code, 400)


class TokenRefreshTests(TestCase):
    """Test token refresh functionality."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser@example.com',
            email='testuser@example.com',
            password='testpass123456'
        )

        refresh = RefreshToken.for_user(self.user)
        self.refresh_token = str(refresh)
        self.old_access_token = str(refresh.access_token)

    def test_refresh_token_generates_new_access_token(self):
        """Refresh token should generate new access token"""
        response = self.client.post('/api/auth/refresh/', {
            'refresh': self.refresh_token
        }, content_type='application/json')

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('access', data)

        # New access token should be different from old one
        new_access_token = data['access']
        self.assertNotEqual(new_access_token, self.old_access_token)

    def test_refresh_with_invalid_token(self):
        """Invalid refresh token should fail"""
        response = self.client.post('/api/auth/refresh/', {
            'refresh': 'invalid.refresh.token'
        }, content_type='application/json')

        # DRF simplejwt returns 400 or 401 for invalid tokens
        self.assertIn(response.status_code, [400, 401])


class TokenBlacklistTests(TestCase):
    """Test token blacklisting on logout."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser@example.com',
            email='testuser@example.com',
            password='testpass123456'
        )

        refresh = RefreshToken.for_user(self.user)
        self.refresh_token = str(refresh)
        self.access_token = str(refresh.access_token)

    def test_logout_blacklists_token(self):
        """Logout should blacklist refresh token"""
        # Logout
        response = self.client.post('/api/auth/logout/', {
            'refresh': self.refresh_token
        }, content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {self.access_token}')

        self.assertEqual(response.status_code, 200)

        # Try to refresh with blacklisted token
        response = self.client.post('/api/auth/refresh/', {
            'refresh': self.refresh_token
        }, content_type='application/json')

        # Should fail because token is blacklisted
        self.assertIn(response.status_code, [400, 401])

    def test_logout_invalidates_session(self):
        """Logout should invalidate Django session"""
        # Create session by logging in
        response = self.client.post('/api/auth/login/email/', {
            'email': 'testuser@example.com',
            'password': 'testpass123456'
        }, content_type='application/json')

        self.assertEqual(response.status_code, 200)

        # Logout
        response = self.client.post('/api/auth/logout/', {
            'refresh': self.refresh_token
        }, content_type='application/json', HTTP_AUTHORIZATION=f'Bearer {self.access_token}')

        self.assertEqual(response.status_code, 200)

        # Session should be flushed (no more session data)
        self.assertEqual(len(self.client.session.keys()), 0)
