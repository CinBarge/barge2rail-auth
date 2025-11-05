#!/usr/bin/env python
"""Assign PrimeTrade role to users in SSO"""

import os

import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from sso.models import ApplicationRole, User


def assign_primetrade_role(email, role="admin", permissions=None):
    """Assign PrimeTrade role to a user.

    Args:
        email: User email address
        role: Role to assign (admin/user/viewer/operator)
        permissions: Optional list of permissions
    """
    if permissions is None:
        permissions = ["full_access"] if role == "admin" else []

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        print(f"❌ User not found: {email}")
        return None

    app_role, created = ApplicationRole.objects.update_or_create(
        user=user,
        application="primetrade",
        defaults={"role": role, "permissions": permissions},
    )

    if created:
        print(f"✅ Created PrimeTrade role for {email}: {role}")
    else:
        print(f"ℹ️  Updated PrimeTrade role for {email}: {role}")

    return app_role


if __name__ == "__main__":
    print("🔐 Assigning PrimeTrade Roles\n")

    # Assign admin role to Clif
    assign_primetrade_role("clif@barge2rail.com", role="admin")

    # Uncomment to assign user role to another user:
    # assign_primetrade_role("user@example.com", role="user")

    print("\n✅ PrimeTrade roles assigned!")
    print("\nNext steps:")
    print("1. Login to PrimeTrade: http://127.0.0.1:8001/")
    print("2. Check logs for '[FLOW DEBUG 6.2]' - should show application_roles in JWT")
    print("3. Verify admin bypass no longer activates")
