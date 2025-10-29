#!/usr/bin/env python3
"""
Google Auth Diagnostic Script

This script will help determine if popup blocking is actually the issue
preventing Google Sign-In from working.
"""

import os
import subprocess
import sys
from pathlib import Path


def check_environment():
    """Check if the environment is properly configured"""
    print("🔍 Checking Environment Configuration")
    print("=" * 50)

    # Check if .env exists
    env_file = Path(".env")
    if env_file.exists():
        print("✅ .env file exists")

        # Read and check environment variables
        with open(".env") as f:
            lines = f.readlines()
            for line in lines:
                if line.strip().startswith("GOOGLE_CLIENT_ID"):
                    client_id = line.split("=", 1)[1].strip()
                    if client_id and client_id != "your-google-client-id":
                        print(f"✅ GOOGLE_CLIENT_ID is configured")
                        print(f"   Client ID: {client_id[:20]}...")
                    else:
                        print("❌ GOOGLE_CLIENT_ID is not properly configured")
                        return False
    else:
        print("❌ .env file not found")
        return False

    return True


def test_server_running():
    """Test if Django server is running"""
    print("\n🌐 Testing Django Server")
    print("=" * 50)

    try:
        import requests

        response = requests.get("http://127.0.0.1:8000/", timeout=5)
        print("✅ Django server is running")
        return True
    except ImportError:
        print("⚠️  requests module not installed - cannot test server")
        return None
    except requests.exceptions.RequestException:
        print("❌ Django server is not running or not accessible")
        print("   Run: python manage.py runserver")
        return False


def analyze_google_diagnostic():
    """Provide analysis of the Google diagnostic results"""
    print("\n🔍 Google Auth Analysis")
    print("=" * 50)

    print("Based on the popup detection in your diagnostic, here's what to check:")
    print()

    print("1. 🪟 POPUP BLOCKING TEST:")
    print("   - Open: http://127.0.0.1:8000/login/google-diagnostic/")
    print("   - Check if popup blocking is actually preventing auth")
    print("   - Most importantly: Try clicking the Google Sign-In button!")
    print()

    print("2. 🧪 ALTERNATIVE TEST:")
    print("   - Open the test_popup.html file I created")
    print("   - Run all 4 popup tests")
    print("   - If Test 3 (User-Initiated) works, popup blocking is NOT the issue")
    print()

    print("3. 🔍 REAL GOOGLE AUTH TEST:")
    print("   - Go to: http://127.0.0.1:8000/login/google-test/")
    print("   - Click the Google Sign-In button")
    print("   - Check browser console (F12) for actual errors")
    print()

    print("4. 📱 COMMON GOOGLE AUTH ISSUES (not popup-related):")
    print("   - ❌ Client ID not configured correctly")
    print("   - ❌ Redirect URI not whitelisted in Google Console")
    print("   - ❌ JavaScript errors in browser console")
    print("   - ❌ CORS issues")
    print("   - ❌ Third-party cookies disabled")
    print()


def provide_solutions():
    """Provide solutions for common Google Auth issues"""
    print("💡 SOLUTIONS TO TRY:")
    print("=" * 50)

    print("If popup blocking is NOT the issue:")
    print("1. Check browser console for JavaScript errors")
    print("2. Verify Google OAuth configuration in Google Console")
    print("3. Test in incognito mode")
    print("4. Try a different browser")
    print("5. Check if third-party cookies are enabled")
    print()

    print("If popup blocking IS the issue:")
    print("1. Use redirect-based auth instead of popup")
    print("2. Ask users to allow popups for your site")
    print("3. Implement Google One Tap (doesn't use popups)")
    print()

    print("Debug commands to run:")
    print("- Check server logs while testing Google auth")
    print("- Use browser dev tools Network tab")
    print("- Test API endpoint directly:")
    print("  curl -X POST http://127.0.0.1:8000/api/auth/login/google/ \\")
    print("       -H 'Content-Type: application/json' \\")
    print('       -d \'{"token":"dummy_token"}\'')


def main():
    print("🚀 Google Authentication Diagnostic")
    print("=" * 50)
    print()

    # Check if we're in the right directory
    if not Path("manage.py").exists():
        print("❌ This script should be run from the Django project root")
        print("   (where manage.py is located)")
        sys.exit(1)

    # Run checks
    env_ok = check_environment()
    if not env_ok:
        print("\n❌ Environment configuration issues found")
        sys.exit(1)

    server_running = test_server_running()

    analyze_google_diagnostic()
    provide_solutions()

    print("\n🔧 NEXT STEPS:")
    print("=" * 50)

    if server_running is False:
        print("1. Start Django server: python manage.py runserver")

    print("2. Open: file://" + str(Path.cwd() / "test_popup.html"))
    print("3. Run popup tests - if they work, popup blocking is NOT your issue")
    print("4. Open: http://127.0.0.1:8000/login/google-diagnostic/")
    print("5. Click the actual Google Sign-In button and check browser console")
    print("6. Look for JavaScript errors, not just popup blocking warnings")


if __name__ == "__main__":
    main()
