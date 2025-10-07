"""
Rate Limiting Tests
Dedicated tests for rate limiting functionality.
"""

from django.test import TestCase, Client, override_settings
from django.core.cache import cache


class RateLimitConfigurationTests(TestCase):
    """Test rate limiting configuration."""

    def setUp(self):
        # Clear cache between tests
        cache.clear()
        self.client = Client()

    @override_settings(RATELIMIT_ENABLE=False)
    def test_rate_limiting_disabled_in_debug(self):
        """Rate limiting should be disabled when DEBUG=True"""
        # Make 10 rapid attempts (would normally be rate limited)
        for i in range(10):
            response = self.client.post('/api/auth/login/email/', {
                'email': 'test@example.com',
                'password': 'wrong'
            }, content_type='application/json')

            # Should get 401 (invalid credentials), not 429 (rate limit)
            self.assertEqual(response.status_code, 401)

    @override_settings(RATELIMIT_ENABLE=True)
    def test_rate_limiting_enabled_in_production(self):
        """Rate limiting should be enabled when DEBUG=False"""
        # Make 6 rapid attempts
        for i in range(6):
            response = self.client.post('/api/auth/login/email/', {
                'email': 'test@example.com',
                'password': 'wrong'
            }, content_type='application/json')

        # Last response should be rate limited
        self.assertEqual(response.status_code, 429)


class RateLimitEndpointTests(TestCase):
    """Test rate limits on specific endpoints."""

    def setUp(self):
        cache.clear()
        self.client = Client()

    @override_settings(RATELIMIT_ENABLE=True)
    def test_oauth_endpoint_rate_limit(self):
        """OAuth endpoint should allow 20 requests per hour"""
        from sso.views import generate_oauth_state

        # Make 20 OAuth attempts (should all succeed without rate limit)
        for i in range(20):
            state = generate_oauth_state()
            session = self.client.session
            session['oauth_state'] = state
            session.save()

            response = self.client.post('/api/auth/login/google/oauth/', {
                'code': f'code_{i}',
                'state': state
            }, content_type='application/json')

            # May get 400/401 (invalid code) but not 429 (rate limit)
            self.assertNotEqual(response.status_code, 429)

        # 21st attempt should be rate limited
        state = generate_oauth_state()
        session = self.client.session
        session['oauth_state'] = state
        session.save()

        response = self.client.post('/api/auth/login/google/oauth/', {
            'code': 'code_21',
            'state': state
        }, content_type='application/json')

        self.assertEqual(response.status_code, 429)

    @override_settings(RATELIMIT_ENABLE=True)
    def test_token_validation_rate_limit(self):
        """Token validation should allow 100 requests per hour"""
        # Make 100 validation attempts (should all succeed/fail normally)
        for i in range(100):
            response = self.client.post('/api/auth/validate/', {
                'token': f'fake_token_{i}'
            }, content_type='application/json')

            # Should get 401 (invalid token), not 429
            self.assertIn(response.status_code, [400, 401])

        # 101st attempt should be rate limited
        response = self.client.post('/api/auth/validate/', {
            'token': 'fake_token_101'
        }, content_type='application/json')

        self.assertEqual(response.status_code, 429)
