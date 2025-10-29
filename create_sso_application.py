#!/usr/bin/env python
"""Create PrimeTrade application in SSO's custom Application model"""

import os

import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from sso.models import Application, User

# Get user
user = User.objects.get(email="clif@barge2rail.com")

# Create or get PrimeTrade application in SSO's Application model
app, created = Application.objects.get_or_create(
    client_id="Le0IwNotn3W1pw2cf1O6o0oWnwM9qOwWDCB3BMlN",
    defaults={
        "name": "PrimeTrade",
        "slug": "primetrade",
        "description": "PrimeTrade application for barge2rail",
        "client_type": "confidential",
        "authorization_grant_type": "authorization-code",
        "redirect_uris": "http://127.0.0.1:8001/auth/callback/\nhttp://localhost:8001/auth/callback/",
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
print(f"Client ID: {app.client_id}")
print(f"Client Secret: {app.client_secret}")
print(f"Is Active: {app.is_active}")
print(f"\n✅ PrimeTrade .env already has the correct client_id!")
print(f"⚠️  UPDATE CLIENT SECRET in .env:")
print(f"SSO_CLIENT_SECRET={app.client_secret}")
