"""
SSO Utilities Package

This package contains utility functions for OAuth admin integration:
- permissions.py: Email whitelist and permission management
- session.py: OAuth token validation and session management
"""

from .permissions import (
    should_grant_admin_access,
    should_grant_superuser_access,
    get_admin_whitelist,
    get_superuser_whitelist,
    assign_admin_permissions,
    revoke_admin_permissions,
)

from .session import (
    validate_oauth_token,
    get_user_from_token,
    create_admin_session,
)

__all__ = [
    # Permission management
    'should_grant_admin_access',
    'should_grant_superuser_access',
    'get_admin_whitelist',
    'get_superuser_whitelist',
    'assign_admin_permissions',
    'revoke_admin_permissions',

    # Session management
    'validate_oauth_token',
    'get_user_from_token',
    'create_admin_session',
]
