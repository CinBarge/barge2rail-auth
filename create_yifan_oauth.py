#!/usr/bin/env python
"""
Register Yifan application in SSO system.

Run from barge2rail-auth directory:
  cd ~/Projects/barge2rail-auth
  python create_yifan_oauth.py
"""

import os
import secrets

import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from sso.models import Application, User

# Get admin user
user = User.objects.get(email="clif@barge2rail.com")

# Generate secure client credentials
client_id = f"yifan_{secrets.token_urlsafe(16)}"

# Create or get Yifan application
app, created = Application.objects.get_or_create(
    slug="yifan",
    defaults={
        "name": "Yifan Coil Tracking",
        "client_id": client_id,
        "description": "Wire rod coil tracking and BOL generation for Yifan Shipping",
        "client_type": "confidential",
        "authorization_grant_type": "authorization-code",
        "redirect_uris": (
            "http://localhost:8000/auth/callback/\n"
            "http://127.0.0.1:8000/auth/callback/\n"
            "https://yifan.barge2rail.com/auth/callback/"
        ),
        "user": user,
        "is_active": True,
        "skip_authorization": False,
    },
)

if created:
    print(f"✅ Created SSO Application: {app.name}")
else:
    print(f"ℹ️  SSO Application already exists: {app.name}")

print(f"\n📋 Application Details:")
print(f"Name: {app.name}")
print(f"Slug: {app.slug}")
print(f"Client ID: {app.client_id}")
print(f"Client Secret: {app.client_secret}")
print(f"Redirect URIs:\n{app.redirect_uris}")
print(f"Is Active: {app.is_active}")

print(f"\n" + "=" * 60)
print(f"ADD TO YIFAN .env FILE:")
print(f"=" * 60)
print(f"SSO_CLIENT_ID={app.client_id}")
print(f"SSO_CLIENT_SECRET={app.client_secret}")
print(f"=" * 60)
