"""
JWKS (JSON Web Key Set) endpoint for JWT signature verification.

This endpoint provides the public key used to verify JWTs signed by this SSO.
Client applications (like PrimeTrade) fetch this to verify token signatures.
"""

import base64
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET

logger = logging.getLogger(__name__)


def _rsa_public_numbers_to_jwk(public_key):
    """
    Convert RSA public key to JWK format.

    Args:
        public_key: RSA public key object

    Returns:
        dict: JWK representation with kty, use, alg, n, e
    """
    public_numbers = public_key.public_numbers()

    # Convert modulus (n) and exponent (e) to base64url
    def int_to_base64url(num):
        """Convert integer to base64url-encoded string."""
        # Get bytes representation
        num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder="big")
        # Base64url encode (no padding)
        return base64.urlsafe_b64encode(num_bytes).rstrip(b"=").decode("utf-8")

    return {
        "kty": "RSA",
        "use": "sig",  # Signature use
        "alg": "RS256",
        "kid": "barge2rail-sso-2025",  # Key ID
        "n": int_to_base64url(public_numbers.n),  # Modulus
        "e": int_to_base64url(public_numbers.e),  # Exponent
    }


@csrf_exempt  # JWKS is public, no CSRF protection needed
@require_GET
def jwks_endpoint(request):
    """
    JWKS endpoint - provides public keys for JWT signature verification.

    Standard path: /.well-known/jwks.json

    Returns:
        JsonResponse: JWKS document with public key
    """
    try:
        # Get RSA private key from settings
        private_key_pem = settings.OAUTH2_PROVIDER.get("OIDC_RSA_PRIVATE_KEY", "")

        if not private_key_pem:
            logger.error("OIDC_RSA_PRIVATE_KEY not configured in settings")
            return JsonResponse(
                {"error": "JWKS unavailable - key not configured"}, status=500
            )

        # Load private key
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode("utf-8"),
                password=None,
                backend=default_backend(),
            )
        except Exception as e:
            logger.error(f"Failed to load RSA private key: {e}")
            return JsonResponse(
                {"error": "JWKS unavailable - invalid key format"}, status=500
            )

        # Extract public key
        public_key = private_key.public_key()

        # Convert to JWK format
        jwk = _rsa_public_numbers_to_jwk(public_key)

        # JWKS response format
        jwks = {"keys": [jwk]}

        logger.info("JWKS endpoint accessed successfully")

        # Return with appropriate caching headers
        response = JsonResponse(jwks)
        response["Cache-Control"] = "public, max-age=3600"  # Cache for 1 hour
        response["Access-Control-Allow-Origin"] = "*"  # Allow CORS (public endpoint)

        return response

    except Exception as e:
        logger.error(f"JWKS endpoint error: {str(e)}", exc_info=True)
        return JsonResponse({"error": "JWKS unavailable"}, status=500)
