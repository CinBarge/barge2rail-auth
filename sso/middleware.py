"""
Session security middleware for barge2rail-auth.
Gate 7: Session Security Hardening
"""
from django.utils import timezone
from django.contrib.auth import logout
from django.contrib import messages
import logging

logger = logging.getLogger('django.security')


class SessionActivityMiddleware:
    """
    Track session activity and enforce idle timeout.

    This middleware:
    1. Tracks last activity timestamp for each session
    2. Enforces 30-minute idle timeout
    3. Logs security events (timeouts)
    4. Provides user feedback on timeout
    """

    IDLE_TIMEOUT_SECONDS = 1800  # 30 minutes

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            current_time = timezone.now()
            last_activity = request.session.get('last_activity')

            if last_activity:
                try:
                    # Parse stored timestamp
                    last_activity_time = timezone.datetime.fromisoformat(last_activity)

                    # Calculate idle time
                    idle_seconds = (current_time - last_activity_time).total_seconds()

                    # Check if session has been idle too long
                    if idle_seconds > self.IDLE_TIMEOUT_SECONDS:
                        user_email = request.user.email
                        idle_minutes = int(idle_seconds / 60)

                        logger.info(
                            f"Session timeout - User: {user_email}, "
                            f"Idle: {idle_minutes} minutes, "
                            f"IP: {request.META.get('REMOTE_ADDR')}"
                        )

                        # Log out user
                        logout(request)

                        # Set message for next request (after redirect)
                        request.session['timeout_message'] = (
                            "Your session expired due to inactivity. "
                            "Please log in again."
                        )

                        # Don't update last_activity - user is being logged out
                        response = self.get_response(request)
                        return response

                except (ValueError, AttributeError, TypeError) as e:
                    # Invalid timestamp format - reset it
                    logger.warning(
                        f"Invalid last_activity timestamp: {last_activity} - "
                        f"Error: {e}"
                    )

            # Update last activity for this request
            request.session['last_activity'] = current_time.isoformat()

        response = self.get_response(request)
        return response
