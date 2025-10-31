#!/usr/bin/env python
"""Create PrimeTrade OAuth application in SSO"""

import os

import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from oauth2_provider.models import Application

from sso.models import User

# Get user
user = User.objects.get(email="clif@barge2rail.com")

# Create or get OAuth application
app, created = Application.objects.get_or_create(
    client_id="app_0b97b7b94d192797",
    defaults={
        "name": "PrimeTrade",
        "client_type": Application.CLIENT_CONFIDENTIAL,
        "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
        "redirect_uris": "http://127.0.0.1:8001/auth/callback/\nhttp://localhost:8001/auth/callback/",
        "user": user,
        "skip_authorization": False,
    },
)

if created:
    print(f"✅ Created OAuth application: {app.name}")
else:
    print(f"ℹ️  OAuth application already exists: {app.name}")

print(f"\n📋 OAuth Application Details:")
print(f"Name: {app.name}")
print(f"Client ID: {app.client_id}")
print(f"Client Secret: {app.client_secret}")
print(f"\n⚠️  IMPORTANT: Copy the Client Secret above!")
print(f"\nNext step: Add to /Users/cerion/Projects/django-primetrade/.env:")
print(f"SSO_CLIENT_SECRET={app.client_secret}")
