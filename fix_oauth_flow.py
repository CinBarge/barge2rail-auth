#!/usr/bin/env python
"""
Fix OAuth Flow Issues - Comprehensive cleanup and testing
"""
import os
import sys
import django
from datetime import datetime

# Setup Django
sys.path.insert(0, '/Users/cerion/Projects/barge2rail-auth')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from sso.models import Application, UserRole, AuthorizationCode
from django.contrib.auth import get_user_model
from django.db import transaction

User = get_user_model()

def cleanup_old_applications():
    """Remove old test applications"""
    print("\n=== Cleaning Up Old Applications ===")
    
    # Get all applications
    apps = Application.objects.all()
    print(f"Found {apps.count()} applications total")
    
    # Keep only PrimeTrade (the one created in October)
    old_apps = Application.objects.exclude(name='PrimeTrade').exclude(client_id='app_0b97b7b94d192797')
    
    if old_apps.exists():
        print(f"\nDeleting {old_apps.count()} old applications:")
        for app in old_apps:
            print(f"  - {app.name} (created {app.created_at})")
            app.delete()
        print("✅ Old applications deleted")
    else:
        print("✅ No old applications to delete")

def ensure_primetrade_setup():
    """Ensure PrimeTrade application is properly configured"""
    print("\n=== Verifying PrimeTrade Setup ===")
    
    try:
        app = Application.objects.get(client_id='app_0b97b7b94d192797')
        print(f"✅ Found PrimeTrade application: {app.name}")
        
        # Update redirect URIs to ensure both local and production are set
        redirect_uris = [
            "http://127.0.0.1:8001/auth/callback/",
            "https://prt.barge2rail.com/auth/callback/"
        ]
        
        app.redirect_uris = "\n".join(redirect_uris)
        app.is_active = True
        app.save()
        
        print("✅ Redirect URIs updated:")
        for uri in redirect_uris:
            print(f"  - {uri}")
            
    except Application.DoesNotExist:
        print("❌ PrimeTrade application not found! This is a problem.")
        return False
    
    # Ensure user role exists
    try:
        user = User.objects.get(email='clif@barge2rail.com')
        
        role, created = UserRole.objects.get_or_create(
            user=user,
            application=app,
            defaults={'role': 'admin'}
        )
        
        if created:
            print(f"✅ Created admin role for {user.email}")
        else:
            print(f"✅ User role exists: {user.email} -> {role.role}")
            
    except User.DoesNotExist:
        print("❌ User clif@barge2rail.com not found!")
        return False
    
    return True

def cleanup_old_auth_codes():
    """Remove expired or used authorization codes"""
    print("\n=== Cleaning Up Authorization Codes ===")
    
    # Delete all authorization codes (they're single-use anyway)
    count = AuthorizationCode.objects.all().count()
    if count > 0:
        AuthorizationCode.objects.all().delete()
        print(f"✅ Deleted {count} authorization codes")
    else:
        print("✅ No authorization codes to clean up")

def test_oauth_urls():
    """Generate test OAuth URLs"""
    print("\n=== OAuth Test URLs ===")
    
    try:
        app = Application.objects.get(client_id='app_0b97b7b94d192797')
        
        print("\n1. Direct OAuth URL (for testing when already logged into SSO):")
        print("-" * 60)
        test_url = (
            "https://sso.barge2rail.com/auth/authorize/"
            "?response_type=code"
            "&client_id=app_0b97b7b94d192797"
            "&redirect_uri=http://127.0.0.1:8001/auth/callback/"
            "&scope=openid email profile"
            "&state=test_from_script"
        )
        print(test_url)
        
        print("\n2. PrimeTrade Login URL:")
        print("-" * 60)
        print("http://127.0.0.1:8001/login/")
        print("Then click 'Login with SSO'")
        
    except Application.DoesNotExist:
        print("❌ Cannot generate test URLs - PrimeTrade app not found")

def main():
    print("=" * 60)
    print("OAuth Flow Cleanup and Fix")
    print("=" * 60)
    
    with transaction.atomic():
        # Clean up old stuff
        cleanup_old_applications()
        cleanup_old_auth_codes()
        
        # Ensure correct setup
        if ensure_primetrade_setup():
            print("\n✅ Setup verified successfully!")
        else:
            print("\n❌ Setup verification failed - manual intervention needed")
            return
    
    # Generate test URLs
    test_oauth_urls()
    
    print("\n" + "=" * 60)
    print("NEXT STEPS:")
    print("1. Clear your browser cookies for both sites")
    print("2. Visit http://127.0.0.1:8001/login/")
    print("3. Click 'Login with SSO'")
    print("4. Complete the OAuth flow")
    print("=" * 60)

if __name__ == "__main__":
    main()
