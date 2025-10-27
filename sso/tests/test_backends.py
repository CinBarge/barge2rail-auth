"""
Unit tests for sso.backends module

Tests custom OAuth authentication backend.
"""

from django.test import TestCase, RequestFactory, override_settings
from django.contrib.auth import get_user_model, authenticate
from unittest.mock import patch, MagicMock
from sso.backends import OAuthBackend

User = get_user_model()


class OAuthBackendAuthenticateTests(TestCase):
    """Test OAuthBackend.authenticate method."""

    def setUp(self):
        """Create request factory."""
        self.factory = RequestFactory()
        self.backend = OAuthBackend()

    def test_none_oauth_token_returns_none(self):
        """Test None oauth_token returns None."""
        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token=None)
        self.assertIsNone(result)

    def test_missing_oauth_token_returns_none(self):
        """Test missing oauth_token parameter returns None."""
        request = self.factory.get('/admin/')
        # Call without oauth_token parameter
        result = self.backend.authenticate(request)
        self.assertIsNone(result)

    @patch('sso.backends.validate_oauth_token')
    def test_invalid_token_returns_none(self, mock_validate):
        """Test invalid OAuth token returns None."""
        # Mock token validation failure
        mock_validate.return_value = (False, None)

        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token='invalid-token')

        self.assertIsNone(result)
        mock_validate.assert_called_once_with('invalid-token')

    @patch('sso.backends.validate_oauth_token')
    def test_token_without_email_returns_none(self, mock_validate):
        """Test token without email returns None."""
        # Mock validation success but no email
        mock_validate.return_value = (True, {'email_verified': True})

        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token='token-no-email')

        self.assertIsNone(result)

    @patch('sso.backends.assign_admin_permissions')
    @patch('sso.backends.get_user_from_token')
    @patch('sso.backends.validate_oauth_token')
    def test_valid_token_creates_and_authenticates_user(
        self, mock_validate, mock_get_user, mock_assign
    ):
        """Test valid OAuth token creates user and authenticates."""
        # Mock successful token validation
        mock_validate.return_value = (True, {
            'email': 'newuser@example.com',
            'email_verified': True,
            'given_name': 'Test',
            'family_name': 'User',
        })

        # Mock user creation
        new_user = User.objects.create(
            email='newuser@example.com',
            username='newuser',
            first_name='Test',
            last_name='User',
        )
        mock_get_user.return_value = new_user

        # Mock permission assignment
        mock_assign.return_value = (True, False, True)

        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token='valid-token')

        self.assertIsNotNone(result)
        self.assertEqual(result.email, 'newuser@example.com')
        mock_validate.assert_called_once_with('valid-token')
        mock_get_user.assert_called_once()
        mock_assign.assert_called_once_with(new_user)

    @patch('sso.backends.assign_admin_permissions')
    @patch('sso.backends.get_user_from_token')
    @patch('sso.backends.validate_oauth_token')
    def test_get_user_from_token_fails_returns_none(
        self, mock_validate, mock_get_user, mock_assign
    ):
        """Test failure to get/create user returns None."""
        # Mock successful validation
        mock_validate.return_value = (True, {
            'email': 'test@example.com',
            'email_verified': True,
        })

        # Mock user creation failure
        mock_get_user.return_value = None

        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token='valid-token')

        self.assertIsNone(result)
        # Should not call assign_admin_permissions if get_user_from_token fails
        mock_assign.assert_not_called()

    @patch('sso.backends.assign_admin_permissions')
    @patch('sso.backends.get_user_from_token')
    @patch('sso.backends.validate_oauth_token')
    @override_settings(
        ADMIN_WHITELIST='test@example.com',
        SUPERUSER_WHITELIST='test@example.com'
    )
    def test_admin_permissions_assigned_correctly(
        self, mock_validate, mock_get_user, mock_assign
    ):
        """Test admin permissions are assigned based on whitelist."""
        # Mock successful validation
        mock_validate.return_value = (True, {
            'email': 'test@example.com',
            'email_verified': True,
        })

        # Create user
        user = User.objects.create(
            email='test@example.com',
            username='test',
        )
        mock_get_user.return_value = user

        # Mock permission assignment (staff and superuser)
        mock_assign.return_value = (True, True, True)

        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token='valid-token')

        self.assertIsNotNone(result)
        self.assertEqual(result.email, 'test@example.com')
        mock_assign.assert_called_once_with(user)

    @patch('sso.backends.validate_oauth_token')
    def test_unexpected_exception_returns_none(self, mock_validate):
        """Test unexpected exception is handled and returns None."""
        # Mock unexpected exception
        mock_validate.side_effect = Exception("Unexpected error")

        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token='problematic-token')

        self.assertIsNone(result)

    @patch('sso.backends.assign_admin_permissions')
    @patch('sso.backends.get_user_from_token')
    @patch('sso.backends.validate_oauth_token')
    def test_authenticate_with_existing_user(
        self, mock_validate, mock_get_user, mock_assign
    ):
        """Test authentication with existing user."""
        # Create existing user
        existing_user = User.objects.create(
            email='existing@example.com',
            username='existing',
            is_staff=False,
            is_superuser=False,
        )

        # Mock successful validation
        mock_validate.return_value = (True, {
            'email': 'existing@example.com',
            'email_verified': True,
        })

        # Mock returning existing user
        mock_get_user.return_value = existing_user

        # Mock no permission changes
        mock_assign.return_value = (False, False, False)

        request = self.factory.get('/admin/')
        result = self.backend.authenticate(request, oauth_token='valid-token')

        self.assertIsNotNone(result)
        self.assertEqual(result.id, existing_user.id)
        self.assertEqual(result.email, 'existing@example.com')


class OAuthBackendGetUserTests(TestCase):
    """Test OAuthBackend.get_user method."""

    def setUp(self):
        """Create test user and backend."""
        self.backend = OAuthBackend()
        self.user = User.objects.create(
            email='test@example.com',
            username='test',
            is_active=True,
        )

    def test_get_user_with_valid_id(self):
        """Test get_user returns user with valid ID."""
        result = self.backend.get_user(self.user.pk)

        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.user.id)
        self.assertEqual(result.email, 'test@example.com')

    def test_get_user_with_invalid_id(self):
        """Test get_user returns None with invalid ID."""
        # Use a UUID that doesn't exist
        import uuid
        invalid_id = uuid.uuid4()

        result = self.backend.get_user(invalid_id)

        self.assertIsNone(result)

    def test_get_user_with_inactive_user(self):
        """Test get_user returns None for inactive user."""
        # Create inactive user
        inactive_user = User.objects.create(
            email='inactive@example.com',
            username='inactive',
            is_active=False,
        )

        result = self.backend.get_user(inactive_user.pk)

        self.assertIsNone(result)

    def test_get_user_with_none_id(self):
        """Test get_user handles None ID gracefully."""
        result = self.backend.get_user(None)

        self.assertIsNone(result)

    def test_get_user_with_string_id(self):
        """Test get_user handles string ID (UUID as string)."""
        result = self.backend.get_user(str(self.user.pk))

        self.assertIsNotNone(result)
        self.assertEqual(result.id, self.user.id)


class OAuthBackendUserCanAuthenticateTests(TestCase):
    """Test OAuthBackend.user_can_authenticate method."""

    def setUp(self):
        """Create backend."""
        self.backend = OAuthBackend()

    def test_active_user_can_authenticate(self):
        """Test active user can authenticate."""
        user = User.objects.create(
            email='active@example.com',
            username='active',
            is_active=True,
        )

        result = self.backend.user_can_authenticate(user)

        self.assertTrue(result)

    def test_inactive_user_cannot_authenticate(self):
        """Test inactive user cannot authenticate."""
        user = User.objects.create(
            email='inactive@example.com',
            username='inactive',
            is_active=False,
        )

        result = self.backend.user_can_authenticate(user)

        self.assertFalse(result)

    def test_user_without_is_active_can_authenticate(self):
        """Test user without is_active attribute can authenticate."""
        # Create a mock user without is_active
        class MinimalUser:
            pass

        user = MinimalUser()

        result = self.backend.user_can_authenticate(user)

        # Should return True when is_active is None
        self.assertTrue(result)


class OAuthBackendIntegrationTests(TestCase):
    """Integration tests using Django's authenticate() function."""

    @patch('sso.backends.assign_admin_permissions')
    @patch('sso.backends.get_user_from_token')
    @patch('sso.backends.validate_oauth_token')
    def test_authenticate_function_with_oauth_token(
        self, mock_validate, mock_get_user, mock_assign
    ):
        """Test Django's authenticate() function works with OAuthBackend."""
        # Mock successful validation
        mock_validate.return_value = (True, {
            'email': 'test@example.com',
            'email_verified': True,
        })

        # Create user
        user = User.objects.create(
            email='test@example.com',
            username='test',
        )
        mock_get_user.return_value = user

        # Mock permission assignment
        mock_assign.return_value = (True, False, True)

        # Use Django's authenticate() function
        factory = RequestFactory()
        request = factory.get('/admin/')
        result = authenticate(request, oauth_token='valid-token')

        self.assertIsNotNone(result)
        self.assertEqual(result.email, 'test@example.com')

    def test_authenticate_function_without_oauth_token_falls_back(self):
        """Test authenticate() falls back to ModelBackend without oauth_token."""
        # Create user with password
        user = User.objects.create_user(
            email='password@example.com',
            username='password',
            password='testpass123',
        )

        # Use Django's authenticate() with username/password
        factory = RequestFactory()
        request = factory.get('/admin/')
        result = authenticate(request, username='password@example.com', password='testpass123')

        # Should authenticate via ModelBackend (password-based)
        self.assertIsNotNone(result)
        self.assertEqual(result.email, 'password@example.com')

    @override_settings(
        ADMIN_WHITELIST='admin@barge2rail.com',
        SUPERUSER_WHITELIST='admin@barge2rail.com'
    )
    @patch('sso.backends.validate_oauth_token')
    def test_full_oauth_flow_with_whitelist(self, mock_validate):
        """Test full OAuth authentication flow with whitelist."""
        # Mock successful token validation
        mock_validate.return_value = (True, {
            'email': 'admin@barge2rail.com',
            'email_verified': True,
            'given_name': 'Admin',
            'family_name': 'User',
        })

        # Authenticate (should create user and assign permissions)
        factory = RequestFactory()
        request = factory.get('/admin/')
        user = authenticate(request, oauth_token='valid-token')

        # Verify user was created
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'admin@barge2rail.com')

        # Verify permissions were assigned
        user.refresh_from_db()
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_superuser)

    @override_settings(
        ADMIN_WHITELIST='',
        SUPERUSER_WHITELIST=''
    )
    @patch('sso.backends.validate_oauth_token')
    def test_oauth_flow_without_whitelist_denies_permissions(self, mock_validate):
        """Test OAuth with empty whitelist denies admin permissions."""
        # Mock successful token validation
        mock_validate.return_value = (True, {
            'email': 'user@example.com',
            'email_verified': True,
            'given_name': 'Regular',
            'family_name': 'User',
        })

        # Authenticate
        factory = RequestFactory()
        request = factory.get('/admin/')
        user = authenticate(request, oauth_token='valid-token')

        # User should be created but without admin permissions
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'user@example.com')

        user.refresh_from_db()
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
