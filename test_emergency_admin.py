#!/usr/bin/env python
"""
Test script to verify emergency admin access works.
This tests the emergency admin user can log into Django admin.
"""

import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

from django.test import Client
from django.contrib.auth import get_user_model
from django.conf import settings

# Add testserver to ALLOWED_HOSTS for testing
if 'testserver' not in settings.ALLOWED_HOSTS:
    settings.ALLOWED_HOSTS.append('testserver')

User = get_user_model()

def test_emergency_admin():
    """Test emergency admin can log into Django admin."""

    print("=" * 70)
    print("EMERGENCY ADMIN LOGIN TEST")
    print("=" * 70)

    # Verify user exists
    print("\n1. Verifying emergency admin user exists...")
    try:
        user = User.objects.get(username='emergency_admin')
        print(f"   ✓ User found: {user.username} ({user.email})")
        print(f"   ✓ is_staff: {user.is_staff}")
        print(f"   ✓ is_superuser: {user.is_superuser}")
        print(f"   ✓ is_active: {user.is_active}")
    except User.DoesNotExist:
        print("   ✗ ERROR: emergency_admin user not found!")
        return False

    # Test login with Django test client
    print("\n2. Testing admin login with username/password...")
    client = Client()

    # Try to access admin (should redirect to login)
    response = client.get('/admin/')
    print(f"   - GET /admin/ status: {response.status_code}")
    if response.status_code == 302:
        print(f"   ✓ Redirected to login (as expected for unauthenticated user)")

    # Test password authentication first
    print(f"   - Testing password authentication...")
    password_correct = user.check_password('EmergencyAccess2025!SecurePassword')
    print(f"   - Password check: {password_correct}")
    print(f"   - USERNAME_FIELD: {User.USERNAME_FIELD}")

    if not password_correct:
        print(f"   ✗ Password is incorrect!")
        return False

    # Use email as username (USERNAME_FIELD='email')
    print(f"   - Logging in with email (USERNAME_FIELD='email')...")
    login_success = client.login(
        username='emergency@barge2rail.com',  # username param, but value is email
        password='EmergencyAccess2025!SecurePassword'
    )

    if login_success:
        print(f"   ✓ Login successful")
    else:
        print(f"   ✗ Login failed!")
        # Try with actual username field as fallback
        print(f"   - Retrying with username field...")
        login_success = client.login(
            username='emergency_admin',
            password='EmergencyAccess2025!SecurePassword'
        )
        if login_success:
            print(f"   ✓ Login successful with username field")
        else:
            print(f"   ✗ Both login attempts failed!")
            return False

    # Try to access admin again (should work now)
    response = client.get('/admin/')
    print(f"\n3. Testing admin access after login...")
    print(f"   - GET /admin/ status: {response.status_code}")

    if response.status_code == 200:
        print(f"   ✓ Admin interface accessible")
        print(f"   ✓ Emergency admin login WORKS")
        return True
    else:
        print(f"   ✗ Admin interface not accessible (status {response.status_code})")
        return False

if __name__ == '__main__':
    try:
        success = test_emergency_admin()
        print("\n" + "=" * 70)
        if success:
            print("RESULT: ✓ EMERGENCY ADMIN ACCESS VERIFIED")
            print("=" * 70)
            sys.exit(0)
        else:
            print("RESULT: ✗ EMERGENCY ADMIN ACCESS FAILED")
            print("=" * 70)
            sys.exit(1)
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
