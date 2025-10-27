"""
Unit tests for sso.utils.session module

Tests OAuth token validation and session management.
"""

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from unittest.mock import patch, MagicMock
from sso.utils.session import (
    validate_oauth_token,
    get_user_from_token,
    create_admin_session,
)

User = get_user_model()


class ValidateOAuthTokenTests(TestCase):
    """Test validate_oauth_token function."""

    def test_empty_token_returns_false(self):
        """Test empty token is rejected."""
        is_valid, user_info = validate_oauth_token('')
        self.assertFalse(is_valid)
        self.assertIsNone(user_info)

    def test_none_token_returns_false(self):
        """Test None token is rejected."""
        is_valid, user_info = validate_oauth_token(None)
        self.assertFalse(is_valid)
        self.assertIsNone(user_info)

    @override_settings(GOOGLE_CLIENT_ID='')
    @patch('sso.utils.session.GOOGLE_AUTH_AVAILABLE', True)
    def test_missing_client_id_returns_false(self):
        """Test missing GOOGLE_CLIENT_ID returns False."""
        is_valid, user_info = validate_oauth_token('fake-token')
        self.assertFalse(is_valid)
        self.assertIsNone(user_info)

    @patch('sso.utils.session.GOOGLE_AUTH_AVAILABLE', False)
    def test_google_auth_not_available(self):
        """Test error when Google auth libraries not installed."""
        is_valid, user_info = validate_oauth_token('fake-token')
        self.assertFalse(is_valid)
        self.assertIsNone(user_info)

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.utils.session.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.utils.session.id_token.verify_oauth2_token')
    def test_valid_token_with_verified_email(self, mock_verify):
        """Test valid token with verified email returns user info."""
        # Mock successful token verification
        mock_verify.return_value = {
            'email': 'test@example.com',
            'email_verified': True,
            'given_name': 'Test',
            'family_name': 'User',
            'picture': 'https://example.com/pic.jpg',
            'sub': '123456789',
        }

        is_valid, user_info = validate_oauth_token('valid-token')

        self.assertTrue(is_valid)
        self.assertIsNotNone(user_info)
        self.assertEqual(user_info['email'], 'test@example.com')
        self.assertTrue(user_info['email_verified'])
        self.assertEqual(user_info['given_name'], 'Test')
        self.assertEqual(user_info['family_name'], 'User')

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.utils.session.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.utils.session.id_token.verify_oauth2_token')
    def test_unverified_email_rejected(self, mock_verify):
        """Test token with unverified email is rejected."""
        # Mock token with unverified email
        mock_verify.return_value = {
            'email': 'test@example.com',
            'email_verified': False,  # Not verified
            'given_name': 'Test',
            'family_name': 'User',
        }

        is_valid, user_info = validate_oauth_token('token-with-unverified-email')

        self.assertFalse(is_valid)
        self.assertIsNone(user_info)

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.utils.session.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.utils.session.id_token.verify_oauth2_token')
    def test_missing_email_rejected(self, mock_verify):
        """Test token without email is rejected."""
        # Mock token without email
        mock_verify.return_value = {
            'email_verified': True,
            'given_name': 'Test',
            'family_name': 'User',
        }

        is_valid, user_info = validate_oauth_token('token-without-email')

        self.assertFalse(is_valid)
        self.assertIsNone(user_info)

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.utils.session.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.utils.session.id_token.verify_oauth2_token')
    def test_invalid_token_raises_value_error(self, mock_verify):
        """Test invalid token raises ValueError and is handled."""
        # Mock verification raising ValueError (invalid token)
        mock_verify.side_effect = ValueError("Invalid token")

        is_valid, user_info = validate_oauth_token('invalid-token')

        self.assertFalse(is_valid)
        self.assertIsNone(user_info)

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.utils.session.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.utils.session.id_token.verify_oauth2_token')
    def test_unexpected_exception_handled(self, mock_verify):
        """Test unexpected exceptions are handled gracefully."""
        # Mock unexpected exception
        mock_verify.side_effect = Exception("Unexpected error")

        is_valid, user_info = validate_oauth_token('problematic-token')

        self.assertFalse(is_valid)
        self.assertIsNone(user_info)


class GetUserFromTokenTests(TestCase):
    """Test get_user_from_token function."""

    def test_empty_user_info_returns_none(self):
        """Test empty user_info returns None."""
        user = get_user_from_token(None)
        self.assertIsNone(user)

    def test_user_info_without_email_returns_none(self):
        """Test user_info without email returns None."""
        user_info = {
            'given_name': 'Test',
            'family_name': 'User',
        }
        user = get_user_from_token(user_info)
        self.assertIsNone(user)

    def test_create_new_user_from_token(self):
        """Test creating new user from OAuth token."""
        user_info = {
            'email': 'newuser@example.com',
            'given_name': 'New',
            'family_name': 'User',
        }

        user = get_user_from_token(user_info)

        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'newuser@example.com')
        self.assertEqual(user.first_name, 'New')
        self.assertEqual(user.last_name, 'User')
        self.assertEqual(user.auth_method, 'google')
        self.assertTrue(user.is_active)

    def test_get_existing_user(self):
        """Test retrieving existing user by email."""
        # Create existing user
        existing = User.objects.create(
            email='existing@example.com',
            username='existing',
            first_name='Old',
            last_name='Name',
        )

        user_info = {
            'email': 'existing@example.com',
            'given_name': 'Old',
            'family_name': 'Name',
        }

        user = get_user_from_token(user_info)

        self.assertIsNotNone(user)
        self.assertEqual(user.id, existing.id)
        self.assertEqual(user.email, 'existing@example.com')

    def test_update_existing_user_name(self):
        """Test updating existing user's name from OAuth."""
        # Create existing user with old name
        existing = User.objects.create(
            email='user@example.com',
            username='user',
            first_name='Old',
            last_name='Name',
        )

        # OAuth data with new name
        user_info = {
            'email': 'user@example.com',
            'given_name': 'New',
            'family_name': 'Name',
        }

        user = get_user_from_token(user_info)

        self.assertEqual(user.id, existing.id)
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'New')
        self.assertEqual(user.last_name, 'Name')

    def test_case_insensitive_email_lookup(self):
        """Test email lookup is case-insensitive."""
        # Create user with lowercase email
        existing = User.objects.create(
            email='user@example.com',
            username='user',
        )

        # Look up with uppercase email
        user_info = {
            'email': 'USER@EXAMPLE.COM',
            'given_name': 'Test',
            'family_name': 'User',
        }

        user = get_user_from_token(user_info)

        self.assertEqual(user.id, existing.id)

    def test_unique_username_generation(self):
        """Test unique username generation when collision occurs."""
        # Create user with username that would collide
        User.objects.create(
            email='other@example.com',
            username='testuser',  # This will collide
        )

        user_info = {
            'email': 'testuser@example.com',  # Would generate 'testuser'
            'given_name': 'Test',
            'family_name': 'User',
        }

        user = get_user_from_token(user_info)

        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'testuser@example.com')
        # Username should be different (testuser1, testuser2, etc.)
        self.assertNotEqual(user.username, 'testuser')
        self.assertTrue(user.username.startswith('testuser'))


class CreateAdminSessionTests(TestCase):
    """Test create_admin_session function."""

    def setUp(self):
        """Create test user and request factory."""
        self.factory = RequestFactory()
        self.user = User.objects.create(
            email='admin@example.com',
            username='admin',
            is_staff=True,
            is_superuser=True,
        )

    def test_none_request_returns_false(self):
        """Test None request returns False."""
        result = create_admin_session(None, self.user)
        self.assertFalse(result)

    def test_none_user_returns_false(self):
        """Test None user returns False."""
        request = self.factory.get('/admin/')
        # Need to add session middleware
        from django.contrib.sessions.middleware import SessionMiddleware
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)

        result = create_admin_session(request, None)
        self.assertFalse(result)

    def test_inactive_user_returns_false(self):
        """Test inactive user returns False."""
        request = self.factory.get('/admin/')
        from django.contrib.sessions.middleware import SessionMiddleware
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)

        # Create inactive user
        inactive_user = User.objects.create(
            email='inactive@example.com',
            username='inactive',
            is_active=False,
        )

        result = create_admin_session(request, inactive_user)
        self.assertFalse(result)

    def test_create_session_for_valid_user(self):
        """Test creating session for valid user."""
        request = self.factory.get('/admin/')
        from django.contrib.sessions.middleware import SessionMiddleware
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)

        result = create_admin_session(request, self.user)

        self.assertTrue(result)
        # Check session keys are set
        self.assertIn('_auth_user_id', request.session)
        self.assertIn('_auth_user_backend', request.session)
        self.assertIn('_auth_user_hash', request.session)
        self.assertIn('oauth_authenticated', request.session)
        self.assertIn('oauth_authenticated_at', request.session)

        # Check values
        self.assertEqual(request.session['_auth_user_id'], str(self.user.pk))
        self.assertEqual(request.session['_auth_user_backend'], 'sso.backends.OAuthBackend')
        self.assertTrue(request.session['oauth_authenticated'])

    def test_session_includes_auth_hash(self):
        """Test session includes user's auth hash."""
        request = self.factory.get('/admin/')
        from django.contrib.sessions.middleware import SessionMiddleware
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)

        result = create_admin_session(request, self.user)

        self.assertTrue(result)
        expected_hash = self.user.get_session_auth_hash()
        self.assertEqual(request.session['_auth_user_hash'], expected_hash)

    def test_session_is_saved(self):
        """Test session is saved to database."""
        request = self.factory.get('/admin/')
        from django.contrib.sessions.middleware import SessionMiddleware
        middleware = SessionMiddleware(lambda x: x)
        middleware.process_request(request)
        request.session.save()  # Ensure session has a key

        # Get initial session key
        initial_key = request.session.session_key

        result = create_admin_session(request, self.user)

        self.assertTrue(result)
        # Session should still have a key
        self.assertIsNotNone(request.session.session_key)
