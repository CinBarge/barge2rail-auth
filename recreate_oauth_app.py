#!/usr/bin/env python
"""Recreate PrimeTrade OAuth application with auto-generated client_id"""

import os

import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from oauth2_provider.models import Application

from sso.models import User

# Delete old application with custom client_id
deleted_count = Application.objects.filter(client_id="app_0b97b7b94d192797").delete()[0]
if deleted_count:
    print(f"🗑️  Deleted old OAuth application")

# Get user
user = User.objects.get(email="clif@barge2rail.com")

# Create new application with auto-generated client_id
app = Application.objects.create(
    name="PrimeTrade",
    client_type=Application.CLIENT_CONFIDENTIAL,
    authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
    redirect_uris="http://127.0.0.1:8001/auth/callback/\nhttp://localhost:8001/auth/callback/",
    user=user,
)

print(f"✅ Created OAuth application: {app.name}")
print(f"\n📋 COPY THESE TO /Users/cerion/Projects/django-primetrade/.env:")
print(f"\nSSO_CLIENT_ID={app.client_id}")
print(f"SSO_CLIENT_SECRET={app.client_secret}")
print(f"\n⚠️  IMPORTANT: Update PrimeTrade's .env file with these values!")
