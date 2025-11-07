"""
Tests for JWKS endpoint - JWT signature verification support
"""

import base64

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.test import Client, TestCase
from django.urls import reverse


class JWKSEndpointTests(TestCase):
    """Test JWKS endpoint returns valid public key for JWT verification"""

    def setUp(self):
        self.client = Client()
        self.jwks_url = reverse("jwks")  # /api/auth/.well-known/jwks.json

    def test_jwks_endpoint_returns_200(self):
        """JWKS endpoint should be publicly accessible"""
        response = self.client.get(self.jwks_url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")

    def test_jwks_response_format(self):
        """JWKS response should match standard format"""
        response = self.client.get(self.jwks_url)
        data = response.json()

        # Standard JWKS format
        self.assertIn("keys", data)
        self.assertIsInstance(data["keys"], list)
        self.assertGreater(len(data["keys"]), 0)

        # Check first key structure
        key = data["keys"][0]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["use"], "sig")
        self.assertEqual(key["alg"], "RS256")
        self.assertIn("kid", key)
        self.assertIn("n", key)  # Modulus
        self.assertIn("e", key)  # Exponent

    def test_jwks_key_can_verify_jwt(self):
        """Public key from JWKS should verify JWT signed with private key"""
        # Get JWKS response
        response = self.client.get(self.jwks_url)
        jwks = response.json()
        jwk = jwks["keys"][0]

        # Construct public key from JWK
        def base64url_decode(input_str):
            """Decode base64url string"""
            padding = "=" * (4 - len(input_str) % 4)
            return base64.urlsafe_b64decode(input_str + padding)

        n = int.from_bytes(base64url_decode(jwk["n"]), byteorder="big")
        e = int.from_bytes(base64url_decode(jwk["e"]), byteorder="big")

        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

        public_numbers = RSAPublicNumbers(e, n)
        public_key = public_numbers.public_key(default_backend())

        # Load private key from settings
        private_key_pem = settings.OAUTH2_PROVIDER.get("OIDC_RSA_PRIVATE_KEY", "")
        if not private_key_pem:
            self.skipTest("OIDC_RSA_PRIVATE_KEY not configured")

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"), password=None, backend=default_backend()
        )

        # Create a test JWT signed with private key
        payload = {
            "sub": "test-user",
            "email": "test@example.com",
            "aud": "test-client",
            "iss": (
                f"{settings.OAUTH2_PROVIDER.get('BASE_URL', 'http://localhost:8000')}"
                "/o"
            ),
        }

        token = jwt.encode(
            payload, private_key, algorithm="RS256", headers={"kid": jwk["kid"]}
        )

        # Verify JWT with public key from JWKS
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_aud": False,
                "verify_iss": False,
            },
        )

        self.assertEqual(decoded["sub"], "test-user")
        self.assertEqual(decoded["email"], "test@example.com")

    def test_jwks_has_caching_headers(self):
        """JWKS should have appropriate caching headers"""
        response = self.client.get(self.jwks_url)
        self.assertIn("Cache-Control", response)
        self.assertIn("public", response["Cache-Control"])

    def test_jwks_allows_cors(self):
        """JWKS should allow CORS for client applications"""
        response = self.client.get(self.jwks_url)
        self.assertEqual(response["Access-Control-Allow-Origin"], "*")

    def test_jwks_no_csrf_required(self):
        """JWKS is public endpoint - should not require CSRF token"""
        # Direct GET without CSRF token should work
        response = self.client.get(self.jwks_url)
        self.assertEqual(response.status_code, 200)
