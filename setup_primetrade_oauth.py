#!/usr/bin/env python
"""
Setup script for PrimeTrade OAuth application.

Creates or updates the PrimeTrade OAuth application with proper configuration:
- Skip authorization (first-party app)
- RS256 algorithm for OpenID Connect token signing
- Proper redirect URIs for development and production
"""

import os

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from sso.models import Application


def setup_primetrade_oauth():
    """Create or update PrimeTrade OAuth application."""

    # Configuration
    app_name = "PrimeTrade"
    redirect_uris = [
        # Development
        "http://localhost:3000/auth/callback/",
        "http://127.0.0.1:3000/auth/callback/",
        "http://localhost:8001/auth/callback/",
        "http://127.0.0.1:8001/auth/callback/",
        # Production (update with actual PrimeTrade domain)
        "https://django-primetrade.onrender.com/auth/callback/",
    ]

    # Check if application exists
    app, created = Application.objects.get_or_create(
        name=app_name,
        defaults={
            "client_type": Application.CLIENT_CONFIDENTIAL,
            "authorization_grant_type": Application.GRANT_AUTHORIZATION_CODE,
            "redirect_uris": "\n".join(redirect_uris),
            "skip_authorization": True,  # First-party app - no consent screen
            "algorithm": "RS256",  # Required for OpenID Connect signed tokens
            "slug": "primetrade",
            "description": "PrimeTrade Logistics Application - First-party app for B2R operations",
            "is_active": True,
        },
    )

    if created:
        print(f"✅ Created new OAuth application: {app_name}")
        print(f"   Client ID: {app.client_id}")
        print(f"   Client Secret: {app.client_secret}")
        print(f"   Algorithm: {app.algorithm}")
        print(f"   Skip Authorization: {app.skip_authorization}")
        print(f"\n⚠️  IMPORTANT: Save the client secret - it won't be shown again!")
        print(f"\n   Add these to PrimeTrade's .env file:")
        print(f"   OAUTH_CLIENT_ID={app.client_id}")
        print(f"   OAUTH_CLIENT_SECRET={app.client_secret}")
    else:
        # Update existing application
        app.redirect_uris = "\n".join(redirect_uris)
        app.skip_authorization = True
        app.algorithm = "RS256"
        app.client_type = Application.CLIENT_CONFIDENTIAL
        app.authorization_grant_type = Application.GRANT_AUTHORIZATION_CODE
        app.save()

        print(f"✅ Updated existing OAuth application: {app_name}")
        print(f"   Client ID: {app.client_id}")
        print(f"   Algorithm: {app.algorithm}")
        print(f"   Skip Authorization: {app.skip_authorization}")
        print(f"\n   Client secret is already set (not displayed for security)")

    print(f"\n📋 Configuration Summary:")
    print(f"   Name: {app.name}")
    print(f"   Client Type: {app.client_type}")
    print(f"   Grant Type: {app.authorization_grant_type}")
    print(f"   Skip Authorization: {app.skip_authorization} (no consent screen)")
    print(f"   Algorithm: {app.algorithm} (for OpenID Connect)")
    print(f"   Redirect URIs:")
    for uri in redirect_uris:
        print(f"     - {uri}")

    print(f"\n✅ PrimeTrade OAuth application is ready!")
    print(f"\n🔗 Next Steps:")
    print(f"   1. Copy the client credentials to PrimeTrade's environment")
    print(f"   2. Configure PrimeTrade to use SSO OAuth endpoints:")
    print(f"      - Authorization: https://sso.barge2rail.com/o/authorize/")
    print(f"      - Token: https://sso.barge2rail.com/o/token/")
    print(f"      - Userinfo: https://sso.barge2rail.com/o/userinfo/")
    print(f"   3. Request scopes: openid email profile")


if __name__ == "__main__":
    setup_primetrade_oauth()
