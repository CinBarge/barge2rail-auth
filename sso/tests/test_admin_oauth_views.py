"""
Unit tests for sso.admin_oauth_views

Tests admin OAuth authentication views.
"""

from django.test import TestCase, Client, override_settings
from django.contrib.auth import get_user_model
from django.urls import reverse
from unittest.mock import patch, MagicMock
from sso.admin_oauth_views import (
    generate_oauth_state,
    validate_oauth_state,
    exchange_google_code_for_tokens,
    validate_google_id_token,
)
import time

User = get_user_model()


class GenerateOAuthStateTests(TestCase):
    """Test generate_oauth_state function."""

    def test_generates_non_empty_state(self):
        """Test state token is generated and non-empty."""
        state = generate_oauth_state()
        self.assertIsNotNone(state)
        self.assertGreater(len(state), 0)

    def test_state_contains_timestamp(self):
        """Test state token contains timestamp."""
        state = generate_oauth_state()
        # State format: {token}:{timestamp}
        self.assertIn(':', state)
        parts = state.split(':')
        self.assertEqual(len(parts), 2)
        # Check timestamp is numeric
        self.assertTrue(parts[1].isdigit())

    def test_generates_unique_states(self):
        """Test each call generates unique state."""
        state1 = generate_oauth_state()
        state2 = generate_oauth_state()
        self.assertNotEqual(state1, state2)


class ValidateOAuthStateTests(TestCase):
    """Test validate_oauth_state function."""

    def test_valid_state_returns_true(self):
        """Test valid state returns True."""
        state = generate_oauth_state()
        result = validate_oauth_state(state, state)
        self.assertTrue(result)

    def test_mismatched_state_returns_false(self):
        """Test mismatched states return False."""
        state1 = generate_oauth_state()
        state2 = generate_oauth_state()
        result = validate_oauth_state(state1, state2)
        self.assertFalse(result)

    def test_missing_callback_state_returns_false(self):
        """Test missing callback state returns False."""
        state = generate_oauth_state()
        result = validate_oauth_state(None, state)
        self.assertFalse(result)

    def test_missing_session_state_returns_false(self):
        """Test missing session state returns False."""
        state = generate_oauth_state()
        result = validate_oauth_state(state, None)
        self.assertFalse(result)

    def test_expired_state_returns_false(self):
        """Test expired state returns False."""
        # Create state with old timestamp (manually)
        old_timestamp = str(int(time.time()) - 400)  # 400 seconds ago
        old_state = f"old_token_12345:{old_timestamp}"
        result = validate_oauth_state(old_state, old_state, timeout=300)
        self.assertFalse(result)

    def test_recent_state_within_timeout_returns_true(self):
        """Test recent state within timeout returns True."""
        state = generate_oauth_state()
        result = validate_oauth_state(state, state, timeout=300)
        self.assertTrue(result)

    def test_invalid_format_returns_false(self):
        """Test invalid state format returns False."""
        invalid_state = "no_colon_no_timestamp"
        result = validate_oauth_state(invalid_state, invalid_state)
        self.assertFalse(result)


class AdminOAuthLoginViewTests(TestCase):
    """Test admin_oauth_login view."""

    def setUp(self):
        """Create test client."""
        self.client = Client()
        self.url = reverse('admin_oauth_login')

    @override_settings(
        GOOGLE_CLIENT_ID='test-client-id',
        GOOGLE_CLIENT_SECRET='test-secret',
        BASE_URL='https://sso.barge2rail.com'
    )
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    def test_initiates_oauth_flow(self):
        """Test view initiates OAuth flow and redirects to Google."""
        response = self.client.get(self.url)

        # Should redirect to Google OAuth
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.url.startswith('https://accounts.google.com/o/oauth2/v2/auth'))

    @override_settings(
        GOOGLE_CLIENT_ID='test-client-id',
        GOOGLE_CLIENT_SECRET='test-secret',
        BASE_URL='https://sso.barge2rail.com'
    )
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    def test_stores_state_in_session(self):
        """Test view stores OAuth state in session."""
        response = self.client.get(self.url)

        # State should be stored in session
        self.assertIn('admin_oauth_state', self.client.session)
        state = self.client.session['admin_oauth_state']
        self.assertIsNotNone(state)
        self.assertGreater(len(state), 0)

    @override_settings(
        GOOGLE_CLIENT_ID='test-client-id',
        GOOGLE_CLIENT_SECRET='test-secret',
        BASE_URL='https://sso.barge2rail.com'
    )
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    def test_stores_next_url_in_session(self):
        """Test view stores next URL in session."""
        response = self.client.get(self.url + '?next=/admin/users/')

        # Next URL should be stored in session
        self.assertIn('admin_oauth_next', self.client.session)
        next_url = self.client.session['admin_oauth_next']
        self.assertEqual(next_url, '/admin/users/')

    @override_settings(
        GOOGLE_CLIENT_ID='test-client-id',
        GOOGLE_CLIENT_SECRET='test-secret',
        BASE_URL='https://sso.barge2rail.com'
    )
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    def test_default_next_url_is_admin(self):
        """Test default next URL is /admin/."""
        response = self.client.get(self.url)

        # Default next URL should be /admin/
        next_url = self.client.session.get('admin_oauth_next')
        self.assertEqual(next_url, '/admin/')

    @override_settings(
        GOOGLE_CLIENT_ID='test-client-id',
        GOOGLE_CLIENT_SECRET='test-secret',
        BASE_URL='https://sso.barge2rail.com'
    )
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    def test_redirect_url_contains_required_parameters(self):
        """Test redirect URL contains all required OAuth parameters."""
        response = self.client.get(self.url)

        redirect_url = response.url
        self.assertIn('client_id=test-client-id', redirect_url)
        self.assertIn('redirect_uri=', redirect_url)
        self.assertIn('response_type=code', redirect_url)
        self.assertIn('scope=openid+email+profile', redirect_url)
        self.assertIn('state=', redirect_url)

    @override_settings(
        GOOGLE_CLIENT_ID='',
        GOOGLE_CLIENT_SECRET='test-secret'
    )
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    def test_missing_client_id_redirects_to_login(self):
        """Test missing client ID redirects to login with error."""
        response = self.client.get(self.url, follow=True)

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')

    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', False)
    def test_google_auth_not_available_redirects_to_login(self):
        """Test Google auth not available redirects to login."""
        response = self.client.get(self.url, follow=True)

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')


class AdminOAuthCallbackViewTests(TestCase):
    """Test admin_oauth_callback view."""

    def setUp(self):
        """Create test client and URL."""
        self.client = Client()
        self.url = reverse('admin_oauth_callback')

    def test_missing_code_redirects_to_login(self):
        """Test missing authorization code redirects to login."""
        response = self.client.get(self.url, follow=True)

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')

    def test_oauth_error_redirects_to_login(self):
        """Test OAuth error redirects to login."""
        response = self.client.get(self.url + '?error=access_denied', follow=True)

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')

    def test_invalid_state_redirects_to_login(self):
        """Test invalid state redirects to login."""
        # Set up session with state
        session = self.client.session
        session['admin_oauth_state'] = 'valid_state:123456'
        session.save()

        # Call with different state
        response = self.client.get(
            self.url + '?code=test_code&state=invalid_state:654321',
            follow=True
        )

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')

    @override_settings(
        ADMIN_WHITELIST='admin@example.com',
        SUPERUSER_WHITELIST='admin@example.com'
    )
    @patch('sso.admin_oauth_views.authenticate')
    @patch('sso.admin_oauth_views.validate_google_id_token')
    @patch('sso.admin_oauth_views.exchange_google_code_for_tokens')
    def test_successful_admin_oauth_flow(
        self, mock_exchange, mock_validate_token, mock_authenticate
    ):
        """Test complete successful OAuth flow."""
        # Set up session with state
        state = generate_oauth_state()
        session = self.client.session
        session['admin_oauth_state'] = state
        session['admin_oauth_next'] = '/admin/users/'
        session.save()

        # Mock token exchange
        mock_exchange.return_value = {
            'id_token': 'test_id_token_12345',
            'access_token': 'test_access_token',
        }

        # Mock token validation
        mock_validate_token.return_value = {
            'email': 'admin@example.com',
            'email_verified': True,
            'given_name': 'Admin',
            'family_name': 'User',
        }

        # Create admin user
        admin_user = User.objects.create(
            email='admin@example.com',
            username='admin',
            is_staff=True,
            is_superuser=True,
        )

        # Mock authentication
        mock_authenticate.return_value = admin_user

        # Make callback request
        response = self.client.get(
            self.url + f'?code=test_code&state={state}'
        )

        # Should redirect to next URL
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/admin/users/')

        # State should be cleared from session
        self.assertNotIn('admin_oauth_state', self.client.session)

        # OAuth token should be stored in session
        self.assertIn('oauth_token', self.client.session)

    @override_settings(
        ADMIN_WHITELIST='',
        SUPERUSER_WHITELIST=''
    )
    @patch('sso.admin_oauth_views.authenticate')
    @patch('sso.admin_oauth_views.validate_google_id_token')
    @patch('sso.admin_oauth_views.exchange_google_code_for_tokens')
    def test_non_admin_user_denied_access(
        self, mock_exchange, mock_validate_token, mock_authenticate
    ):
        """Test non-admin user is denied access."""
        # Set up session with state
        state = generate_oauth_state()
        session = self.client.session
        session['admin_oauth_state'] = state
        session.save()

        # Mock token exchange
        mock_exchange.return_value = {
            'id_token': 'test_id_token_12345',
            'access_token': 'test_access_token',
        }

        # Mock token validation
        mock_validate_token.return_value = {
            'email': 'user@example.com',
            'email_verified': True,
        }

        # Mock authentication returns None (not in whitelist)
        mock_authenticate.return_value = None

        # Make callback request
        response = self.client.get(
            self.url + f'?code=test_code&state={state}',
            follow=True
        )

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')

    @override_settings(
        ADMIN_WHITELIST='user@example.com',
        SUPERUSER_WHITELIST=''
    )
    @patch('sso.admin_oauth_views.authenticate')
    @patch('sso.admin_oauth_views.validate_google_id_token')
    @patch('sso.admin_oauth_views.exchange_google_code_for_tokens')
    def test_authenticated_but_not_staff_denied(
        self, mock_exchange, mock_validate_token, mock_authenticate
    ):
        """Test authenticated user without is_staff is denied."""
        # Set up session with state
        state = generate_oauth_state()
        session = self.client.session
        session['admin_oauth_state'] = state
        session.save()

        # Mock token exchange
        mock_exchange.return_value = {
            'id_token': 'test_id_token_12345',
            'access_token': 'test_access_token',
        }

        # Mock token validation
        mock_validate_token.return_value = {
            'email': 'user@example.com',
            'email_verified': True,
        }

        # Create non-staff user
        user = User.objects.create(
            email='user@example.com',
            username='user',
            is_staff=False,  # Not staff
        )

        # Mock authentication
        mock_authenticate.return_value = user

        # Make callback request
        response = self.client.get(
            self.url + f'?code=test_code&state={state}',
            follow=True
        )

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')

    @patch('sso.admin_oauth_views.validate_google_id_token')
    @patch('sso.admin_oauth_views.exchange_google_code_for_tokens')
    def test_token_exchange_error_redirects_to_login(
        self, mock_exchange, mock_validate_token
    ):
        """Test token exchange error redirects to login."""
        # Set up session with state
        state = generate_oauth_state()
        session = self.client.session
        session['admin_oauth_state'] = state
        session.save()

        # Mock token exchange error
        mock_exchange.return_value = {
            'error': 'invalid_grant',
            'error_description': 'Code expired',
        }

        # Make callback request
        response = self.client.get(
            self.url + f'?code=test_code&state={state}',
            follow=True
        )

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')

    @patch('sso.admin_oauth_views.validate_google_id_token')
    @patch('sso.admin_oauth_views.exchange_google_code_for_tokens')
    def test_token_validation_failure_redirects_to_login(
        self, mock_exchange, mock_validate_token
    ):
        """Test token validation failure redirects to login."""
        # Set up session with state
        state = generate_oauth_state()
        session = self.client.session
        session['admin_oauth_state'] = state
        session.save()

        # Mock token exchange
        mock_exchange.return_value = {
            'id_token': 'invalid_token',
            'access_token': 'test_access_token',
        }

        # Mock token validation failure
        mock_validate_token.return_value = None

        # Make callback request
        response = self.client.get(
            self.url + f'?code=test_code&state={state}',
            follow=True
        )

        # Should redirect to admin login
        self.assertRedirects(response, '/admin/login/')


class ExchangeGoogleCodeForTokensTests(TestCase):
    """Test exchange_google_code_for_tokens function."""

    @override_settings(
        GOOGLE_CLIENT_ID='test-client-id',
        GOOGLE_CLIENT_SECRET='test-secret',
        BASE_URL='https://sso.barge2rail.com'
    )
    @patch('requests.post')
    def test_successful_token_exchange(self, mock_post):
        """Test successful token exchange returns tokens."""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'access_token': 'test_access_token',
            'id_token': 'test_id_token',
            'expires_in': 3600,
        }
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        result = exchange_google_code_for_tokens('test_code')

        self.assertIn('access_token', result)
        self.assertIn('id_token', result)
        self.assertEqual(result['access_token'], 'test_access_token')

    @override_settings(
        GOOGLE_CLIENT_ID='test-client-id',
        GOOGLE_CLIENT_SECRET='test-secret',
        BASE_URL='https://sso.barge2rail.com'
    )
    @patch('requests.post')
    def test_failed_token_exchange_returns_error(self, mock_post):
        """Test failed token exchange returns error."""
        # Mock request exception
        import requests
        mock_post.side_effect = requests.RequestException("Connection error")

        result = exchange_google_code_for_tokens('test_code')

        self.assertIn('error', result)
        self.assertEqual(result['error'], 'token_exchange_failed')


class ValidateGoogleIdTokenTests(TestCase):
    """Test validate_google_id_token function."""

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.admin_oauth_views.id_token.verify_oauth2_token')
    def test_valid_token_returns_user_info(self, mock_verify):
        """Test valid token returns user information."""
        # Mock token verification
        mock_verify.return_value = {
            'email': 'test@example.com',
            'email_verified': True,
            'given_name': 'Test',
            'family_name': 'User',
            'picture': 'https://example.com/pic.jpg',
            'sub': '123456789',
        }

        result = validate_google_id_token('test_token')

        self.assertIsNotNone(result)
        self.assertEqual(result['email'], 'test@example.com')
        self.assertTrue(result['email_verified'])

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.admin_oauth_views.id_token.verify_oauth2_token')
    def test_unverified_email_returns_none(self, mock_verify):
        """Test unverified email returns None."""
        # Mock token with unverified email
        mock_verify.return_value = {
            'email': 'test@example.com',
            'email_verified': False,  # Not verified
        }

        result = validate_google_id_token('test_token')

        self.assertIsNone(result)

    @override_settings(GOOGLE_CLIENT_ID='test-client-id')
    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', True)
    @patch('sso.admin_oauth_views.id_token.verify_oauth2_token')
    def test_invalid_token_returns_none(self, mock_verify):
        """Test invalid token returns None."""
        # Mock verification failure
        mock_verify.side_effect = ValueError("Invalid token")

        result = validate_google_id_token('invalid_token')

        self.assertIsNone(result)

    @patch('sso.admin_oauth_views.GOOGLE_AUTH_AVAILABLE', False)
    def test_google_auth_not_available_returns_none(self):
        """Test returns None when Google auth not available."""
        result = validate_google_id_token('test_token')

        self.assertIsNone(result)
