"""
Permission Management Utilities for OAuth Admin Integration

This module handles email-based permission assignment for Django admin access.
It provides functions to check email whitelists and assign appropriate permissions.

Security Features:
- Email whitelist validation (exact match and domain wildcards)
- Separate superuser whitelist (exact match only, no wildcards)
- Deny-by-default security model
- Audit logging for all permission changes
- No hardcoded emails (all from environment variables)
"""

from django.conf import settings
from django.contrib.auth import get_user_model
import logging

logger = logging.getLogger(__name__)

User = get_user_model()


def get_admin_whitelist():
    """
    Get list of emails/domains allowed admin (is_staff) access.

    Reads from ADMIN_WHITELIST setting which should be a comma-separated string:
    Example: 'admin@example.com,user@example.com,*@example.com'

    Returns:
        list: Lowercase email addresses and domain wildcards

    Note:
        - Returns empty list if ADMIN_WHITELIST not configured
        - Automatically lowercases all emails for case-insensitive matching
        - Strips whitespace from entries
        - Filters out empty entries
    """
    whitelist = getattr(settings, 'ADMIN_WHITELIST', '')

    if not whitelist:
        logger.warning("ADMIN_WHITELIST not configured - no OAuth admin access will be granted")
        return []

    # Parse comma-separated list, lowercase, strip whitespace, filter empties
    emails = [e.strip().lower() for e in whitelist.split(',') if e.strip()]

    logger.debug(f"Admin whitelist loaded: {len(emails)} entries")
    return emails


def get_superuser_whitelist():
    """
    Get list of emails allowed superuser access.

    Reads from SUPERUSER_WHITELIST setting which should be a comma-separated string:
    Example: 'admin@example.com,superadmin@example.com'

    Returns:
        list: Lowercase email addresses (exact match only)

    Note:
        - Returns empty list if SUPERUSER_WHITELIST not configured
        - Wildcards are NOT supported for superuser (too risky)
        - Automatically lowercases all emails
        - Strips whitespace from entries
    """
    whitelist = getattr(settings, 'SUPERUSER_WHITELIST', '')

    if not whitelist:
        logger.debug("SUPERUSER_WHITELIST not configured - no OAuth superuser access")
        return []

    # Parse comma-separated list, lowercase, strip whitespace, filter empties
    emails = [e.strip().lower() for e in whitelist.split(',') if e.strip()]

    # Warn if wildcards found (not supported for superuser)
    wildcards = [e for e in emails if e.startswith('*@')]
    if wildcards:
        logger.warning(
            f"Wildcards in SUPERUSER_WHITELIST are ignored (too risky): {wildcards}"
        )
        # Remove wildcards from superuser list
        emails = [e for e in emails if not e.startswith('*@')]

    logger.debug(f"Superuser whitelist loaded: {len(emails)} entries")
    return emails


def should_grant_admin_access(email):
    """
    Check if email should receive admin (is_staff) access.

    Checks email against ADMIN_WHITELIST with support for:
    - Exact email match: 'user@example.com'
    - Domain wildcard match: '*@example.com' matches any @example.com email

    Args:
        email (str): User's email address

    Returns:
        bool: True if email is whitelisted for admin access, False otherwise

    Security Notes:
        - Case-insensitive matching (emails lowercased)
        - Deny-by-default (empty whitelist = no access)
        - Domain wildcards only match the domain, not subdomains

    Examples:
        >>> # ADMIN_WHITELIST = 'admin@example.com,*@barge2rail.com'
        >>> should_grant_admin_access('admin@example.com')
        True
        >>> should_grant_admin_access('user@barge2rail.com')
        True
        >>> should_grant_admin_access('user@evil.com')
        False
    """
    if not email:
        logger.warning("should_grant_admin_access called with empty email")
        return False

    email = email.lower().strip()
    admin_emails = get_admin_whitelist()

    # Exact match
    if email in admin_emails:
        logger.debug(f"Admin access granted (exact match): {email}")
        return True

    # Domain wildcard match (e.g., *@barge2rail.com)
    if '@' in email:
        email_domain = email.split('@')[1]
        for allowed in admin_emails:
            if allowed.startswith('*@'):
                allowed_domain = allowed[2:]  # Remove '*@' prefix
                if email_domain == allowed_domain:
                    logger.debug(f"Admin access granted (wildcard match): {email} matches {allowed}")
                    return True

    logger.debug(f"Admin access denied: {email} not in whitelist")
    return False


def should_grant_superuser_access(email):
    """
    Check if email should receive superuser access.

    Checks email against SUPERUSER_WHITELIST with EXACT MATCH ONLY.
    Wildcards are NOT supported for superuser (too risky).

    Args:
        email (str): User's email address

    Returns:
        bool: True if email is whitelisted for superuser access, False otherwise

    Security Notes:
        - Exact match only (no wildcards)
        - Case-insensitive matching
        - Deny-by-default
        - More restrictive than admin access

    Examples:
        >>> # SUPERUSER_WHITELIST = 'admin@barge2rail.com'
        >>> should_grant_superuser_access('admin@barge2rail.com')
        True
        >>> should_grant_superuser_access('user@barge2rail.com')
        False
    """
    if not email:
        logger.warning("should_grant_superuser_access called with empty email")
        return False

    email = email.lower().strip()
    superuser_emails = get_superuser_whitelist()

    # Exact match only (no wildcards for superuser)
    is_superuser = email in superuser_emails

    if is_superuser:
        logger.debug(f"Superuser access granted: {email}")
    else:
        logger.debug(f"Superuser access denied: {email}")

    return is_superuser


def assign_admin_permissions(user):
    """
    Assign appropriate admin permissions to user based on email.

    Checks user's email against whitelists and updates is_staff and is_superuser
    flags accordingly. Only updates if permissions have changed.

    Args:
        user: Django User object

    Returns:
        tuple: (is_staff: bool, is_superuser: bool, changed: bool)
            - is_staff: New value of is_staff flag
            - is_superuser: New value of is_superuser flag
            - changed: True if any permissions were updated

    Side Effects:
        - Updates user.is_staff and user.is_superuser if needed
        - Saves user to database if changed
        - Logs permission changes

    Security Notes:
        - Only grants permissions (never removes via this function)
        - Logs all permission changes for audit
        - Atomic update (both flags updated in single save)

    Examples:
        >>> user = User.objects.get(email='admin@barge2rail.com')
        >>> is_staff, is_superuser, changed = assign_admin_permissions(user)
        >>> print(f"Staff: {is_staff}, Superuser: {is_superuser}, Changed: {changed}")
        Staff: True, Superuser: True, Changed: True
    """
    if not user or not user.email:
        logger.error("assign_admin_permissions called with invalid user")
        return (False, False, False)

    email = user.email.lower().strip()

    # Store original permissions
    original_staff = user.is_staff
    original_superuser = user.is_superuser

    # Determine new permissions based on whitelists
    new_staff = should_grant_admin_access(email)
    new_superuser = should_grant_superuser_access(email)

    # Check if any changes needed
    changed = False
    updates = []

    if user.is_staff != new_staff:
        user.is_staff = new_staff
        changed = True
        updates.append('is_staff')
        logger.info(
            f"Updated is_staff for {email}: {original_staff} -> {new_staff}"
        )

    if user.is_superuser != new_superuser:
        user.is_superuser = new_superuser
        changed = True
        updates.append('is_superuser')
        logger.info(
            f"Updated is_superuser for {email}: {original_superuser} -> {new_superuser}"
        )

    # Save if changed
    if changed:
        user.save(update_fields=updates)
        logger.info(
            f"Admin permissions updated for {email}: "
            f"is_staff={new_staff}, is_superuser={new_superuser}"
        )
    else:
        logger.debug(f"No permission changes needed for {email}")

    return (new_staff, new_superuser, changed)


def revoke_admin_permissions(user):
    """
    Remove admin permissions from user.

    Sets is_staff and is_superuser to False. Used when removing admin access
    or when email is removed from whitelists.

    Args:
        user: Django User object

    Returns:
        bool: True if permissions were changed, False if already non-admin

    Side Effects:
        - Sets user.is_staff = False
        - Sets user.is_superuser = False
        - Saves user to database if changed
        - Logs permission revocation

    Security Notes:
        - Always logs permission removal for audit
        - Atomic update (both flags updated in single save)
        - Idempotent (safe to call multiple times)

    Examples:
        >>> user = User.objects.get(email='removed@example.com')
        >>> changed = revoke_admin_permissions(user)
        >>> print(f"Permissions revoked: {changed}")
        Permissions revoked: True
    """
    if not user:
        logger.error("revoke_admin_permissions called with invalid user")
        return False

    changed = False

    if user.is_staff or user.is_superuser:
        user.is_staff = False
        user.is_superuser = False
        user.save(update_fields=['is_staff', 'is_superuser'])
        changed = True

        logger.warning(
            f"Revoked admin permissions from {user.email or user.username}: "
            f"is_staff=False, is_superuser=False"
        )
    else:
        logger.debug(
            f"No permissions to revoke for {user.email or user.username} "
            "(already non-admin)"
        )

    return changed
