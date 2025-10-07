"""
OAuth Flow Tests
Tests all OAuth-related functionality including state parameter validation,
token exchange, and error handling.
"""

import pytest
from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch, MagicMock
from sso.models import User, TokenExchangeSession
from sso.views import generate_oauth_state, validate_oauth_state
import time


class OAuthStateTests(TestCase):
    """Test OAuth state parameter generation and validation."""

    def test_generate_oauth_state_format(self):
        """Verify OAuth state has correct format: token:timestamp"""
        state = generate_oauth_state()

        # Should be in format: random_token:timestamp
        parts = state.split(':')
        self.assertEqual(len(parts), 2, "State should have token:timestamp format")

        # Token part should be non-empty
        self.assertGreater(len(parts[0]), 30, "Token should be substantial length")

        # Timestamp should be numeric and recent
        timestamp = int(parts[1])
        current_time = int(time.time())
        self.assertLessEqual(abs(current_time - timestamp), 2, "Timestamp should be current")

    def test_validate_oauth_state_success(self):
        """Valid state should pass validation"""
        state = generate_oauth_state()

        result = validate_oauth_state(state, state, timeout=60)
        self.assertTrue(result, "Valid state should pass validation")

    def test_validate_oauth_state_mismatch(self):
        """Mismatched states should fail validation"""
        state1 = generate_oauth_state()
        state2 = generate_oauth_state()

        result = validate_oauth_state(state1, state2, timeout=60)
        self.assertFalse(result, "Mismatched states should fail")

    def test_validate_oauth_state_expired(self):
        """Expired state should fail validation"""
        # Create old state (62 seconds ago, timeout is 60)
        old_timestamp = int(time.time()) - 62
        old_state = f"test_token_12345:{old_timestamp}"

        result = validate_oauth_state(old_state, old_state, timeout=60)
        self.assertFalse(result, "Expired state should fail validation")

    def test_validate_oauth_state_missing(self):
        """Missing state parameters should fail"""
        result = validate_oauth_state(None, "valid_state:123456", timeout=60)
        self.assertFalse(result, "Missing callback state should fail")

        result = validate_oauth_state("valid_state:123456", None, timeout=60)
        self.assertFalse(result, "Missing session state should fail")

    def test_oauth_state_timeout_is_60_seconds(self):
        """Verify OAuth state timeout is 60 seconds (not 300)"""
        # State that's 61 seconds old should fail
        old_timestamp = int(time.time()) - 61
        old_state = f"test_token:{old_timestamp}"

        # Using default timeout (should be 60)
        result = validate_oauth_state(old_state, old_state)
        self.assertFalse(result, "State older than 60 seconds should fail")

        # State that's 59 seconds old should pass
        recent_timestamp = int(time.time()) - 59
        recent_state = f"test_token:{recent_timestamp}"

        result = validate_oauth_state(recent_state, recent_state)
        self.assertTrue(result, "State within 60 seconds should pass")


class OAuthURLGenerationTests(TestCase):
    """Test OAuth URL generation endpoint."""

    def setUp(self):
        self.client = Client()

    def test_oauth_url_generation(self):
        """OAuth URL endpoint should return valid authorization URL"""
        response = self.client.get('/api/auth/oauth/google/url/')

        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('auth_url', data)
        self.assertIn('redirect_uri', data)
        self.assertIn('client_id', data)

        # Verify URL structure
        auth_url = data['auth_url']
        self.assertTrue(auth_url.startswith('https://accounts.google.com/o/oauth2/v2/auth'))
        self.assertIn('state=', auth_url)
        self.assertIn('client_id=', auth_url)
        self.assertIn('redirect_uri=', auth_url)

    def test_oauth_url_stores_state_in_session(self):
        """OAuth URL generation should store state in session"""
        response = self.client.get('/api/auth/oauth/google/url/')

        self.assertEqual(response.status_code, 200)
        self.assertIn('oauth_state', self.client.session)

        stored_state = self.client.session['oauth_state']
        self.assertIsNotNone(stored_state)
        self.assertIn(':', stored_state)  # Should have token:timestamp format


class TokenExchangeSessionTests(TestCase):
    """Test TokenExchangeSession model and cleanup."""

    def test_token_exchange_session_creation(self):
        """TokenExchangeSession should be created with all required fields"""
        from django.utils import timezone
        from datetime import timedelta

        session = TokenExchangeSession.objects.create(
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            user_email='test@example.com',
            expires_at=timezone.now() + timedelta(seconds=60)
        )

        self.assertIsNotNone(session.session_id)
        self.assertFalse(session.used)
        self.assertEqual(session.user_email, 'test@example.com')

    def test_token_exchange_single_use(self):
        """TokenExchangeSession should be marked as used after retrieval"""
        from django.utils import timezone
        from datetime import timedelta

        session = TokenExchangeSession.objects.create(
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            user_email='test@example.com',
            expires_at=timezone.now() + timedelta(seconds=60)
        )

        session_id = session.session_id

        # First retrieval should work
        response = self.client.get(f'/api/auth/session/{session_id}/tokens/')
        self.assertEqual(response.status_code, 200)

        # Session should now be marked as used
        session.refresh_from_db()
        self.assertTrue(session.used)

        # Second retrieval should fail
        response = self.client.get(f'/api/auth/session/{session_id}/tokens/')
        self.assertEqual(response.status_code, 404)

    def test_token_exchange_expiry(self):
        """Expired TokenExchangeSession should return 404"""
        from django.utils import timezone
        from datetime import timedelta

        # Create expired session
        session = TokenExchangeSession.objects.create(
            access_token='test_access_token',
            refresh_token='test_refresh_token',
            user_email='test@example.com',
            expires_at=timezone.now() - timedelta(seconds=1)  # Already expired
        )

        session_id = session.session_id

        # Should return 404 for expired session
        response = self.client.get(f'/api/auth/session/{session_id}/tokens/')
        self.assertEqual(response.status_code, 404)

    def test_token_exchange_cleanup_on_retrieval(self):
        """Expired sessions should be cleaned up during retrieval"""
        from django.utils import timezone
        from datetime import timedelta

        # Create multiple expired sessions
        for i in range(5):
            TokenExchangeSession.objects.create(
                access_token=f'test_token_{i}',
                refresh_token=f'refresh_token_{i}',
                user_email=f'test{i}@example.com',
                expires_at=timezone.now() - timedelta(seconds=10)
            )

        # Create one valid session
        valid_session = TokenExchangeSession.objects.create(
            access_token='valid_token',
            refresh_token='valid_refresh',
            user_email='valid@example.com',
            expires_at=timezone.now() + timedelta(seconds=60)
        )

        initial_count = TokenExchangeSession.objects.count()
        self.assertEqual(initial_count, 6)

        # Retrieve valid session (should trigger cleanup)
        response = self.client.get(f'/api/auth/session/{valid_session.session_id}/tokens/')
        self.assertEqual(response.status_code, 200)

        # Expired sessions should be deleted
        remaining_count = TokenExchangeSession.objects.count()
        self.assertEqual(remaining_count, 1)  # Only the used valid session remains


@pytest.mark.django_db
class OAuthCallbackMockedTests(TestCase):
    """Test OAuth callback with mocked Google responses."""

    @patch('sso.views.exchange_google_code_for_tokens')
    @patch('sso.views.verify_google_id_token')
    def test_oauth_callback_creates_new_user(self, mock_verify, mock_exchange):
        """OAuth callback should create new user for first-time Google login"""
        # Mock Google responses
        mock_exchange.return_value = {
            'access_token': 'google_access_token',
            'refresh_token': 'google_refresh_token',
            'id_token': 'google_id_token'
        }

        mock_verify.return_value = {
            'google_id': '123456789',
            'email': 'newuser@example.com',
            'name': 'New User',
            'picture': 'https://example.com/photo.jpg',
            'email_verified': True
        }

        # Simulate OAuth callback
        state = generate_oauth_state()
        session = self.client.session
        session['oauth_state'] = state
        session.save()

        response = self.client.post('/api/auth/login/google/oauth/', {
            'code': 'auth_code_12345',
            'state': state
        }, content_type='application/json')

        self.assertEqual(response.status_code, 200)

        # Verify user was created
        user = User.objects.get(email='newuser@example.com')
        self.assertEqual(user.google_id, '123456789')
        self.assertEqual(user.auth_type, 'google')
        self.assertTrue(user.is_active)

    @patch('sso.views.exchange_google_code_for_tokens')
    @patch('sso.views.verify_google_id_token')
    def test_oauth_callback_updates_existing_user(self, mock_verify, mock_exchange):
        """OAuth callback should update existing user on subsequent logins"""
        # Create existing user
        existing_user = User.objects.create(
            email='existing@example.com',
            google_id='987654321',
            auth_type='google',
            display_name='Old Name',
            username='existing@example.com'
        )

        # Mock Google responses with updated name
        mock_exchange.return_value = {
            'access_token': 'google_access_token',
            'id_token': 'google_id_token'
        }

        mock_verify.return_value = {
            'google_id': '987654321',
            'email': 'existing@example.com',
            'name': 'Updated Name',
            'picture': 'https://example.com/photo.jpg',
            'email_verified': True
        }

        # Simulate OAuth callback
        state = generate_oauth_state()
        session = self.client.session
        session['oauth_state'] = state
        session.save()

        response = self.client.post('/api/auth/login/google/oauth/', {
            'code': 'auth_code_12345',
            'state': state
        }, content_type='application/json')

        self.assertEqual(response.status_code, 200)

        # Verify user was updated
        existing_user.refresh_from_db()
        self.assertEqual(existing_user.display_name, 'Updated Name')
