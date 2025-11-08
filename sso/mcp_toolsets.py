"""
MCP toolsets for SSO models.

Provides AI agents with access to User and ApplicationRole data
for the barge2rail-auth Django SSO system.
"""

from mcp_server.toolsets import ModelQueryToolset

from sso.models import ApplicationRole, User


class UserToolset(ModelQueryToolset):
    """
    Exposes User model to MCP clients.

    Allows querying users by email, viewing authentication methods,
    and checking admin status.
    """

    model = User
    fields = [
        "id",
        "email",
        "display_name",
        "phone",
        "is_active",
        "is_sso_admin",
        "auth_type",
        "auth_method",
        "google_id",
        "created_at",
        "updated_at",
    ]
    search_fields = ["email", "display_name"]
    filterset_fields = {
        "is_active": ["exact"],
        "is_sso_admin": ["exact"],
        "auth_type": ["exact"],
        "auth_method": ["exact"],
    }


class ApplicationRoleToolset(ModelQueryToolset):
    """
    Exposes ApplicationRole model to MCP clients.

    Allows querying user roles across different applications
    (PrimeTrade, Database, Repair, etc.) and their permissions.
    """

    model = ApplicationRole
    fields = [
        "id",
        "user",
        "application",
        "role",
        "permissions",
        "assigned_date",
        "notes",
    ]
    search_fields = ["user__email", "application", "role"]
    filterset_fields = {
        "application": ["exact"],
        "role": ["exact"],
        "user__email": ["exact"],
    }
