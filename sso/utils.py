"""
Utility functions for SSO application
"""

from django_ratelimit.exceptions import Ratelimited
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler


def custom_exception_handler(exc, context):
    """
    Custom exception handler for DRF that handles rate limiting exceptions.

    Converts django-ratelimit's Ratelimited exception to HTTP 429 response.
    """
    # Handle rate limiting exception
    if isinstance(exc, Ratelimited):
        return Response(
            {"error": "Too many requests. Please try again later."},
            status=status.HTTP_429_TOO_MANY_REQUESTS,
        )

    # Call DRF's default exception handler for all other exceptions
    return exception_handler(exc, context)
