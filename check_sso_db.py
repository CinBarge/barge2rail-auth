#!/usr/bin/env python
"""
Check SSO database for applications and clean up old ones
"""
import os
import sys

import django

# Setup Django
sys.path.insert(0, "/Users/cerion/Projects/barge2rail-auth")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from django.contrib.auth import get_user_model

from sso.models import Application, UserRole

User = get_user_model()

print("\n=== SSO Database Check ===\n")

# Check all applications
print("Current Applications:")
print("-" * 50)
apps = Application.objects.all().order_by("created")
for app in apps:
    print(f"Name: {app.name}")
    print(f"  Client ID: {app.client_id}")
    print(f"  Created: {app.created}")
    print(f"  Active: {app.is_active}")
    print(f"  Redirect URIs: {app.redirect_uris}")
    print()

# Check user roles
print("\nUser Roles:")
print("-" * 50)
roles = UserRole.objects.all()
for role in roles:
    print(f"User: {role.user.email} -> App: {role.application.name} ({role.role})")

# Check for clif's user
print("\nUser Check:")
print("-" * 50)
try:
    user = User.objects.get(email="clif@barge2rail.com")
    print(f"User found: {user.email}")
    print(f"  ID: {user.id}")
    print(
        f"  Is SSO Admin: {user.is_sso_admin if hasattr(user, 'is_sso_admin') else 'N/A'}"
    )
    print(f"  Created: {user.date_joined}")
except User.DoesNotExist:
    print("User clif@barge2rail.com not found")

print("\n" + "=" * 50)
print("To clean up old applications, run:")
print("Application.objects.filter(created__lt='2025-12-01').delete()")
print("=" * 50)
