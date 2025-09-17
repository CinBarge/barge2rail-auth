#!/usr/bin/env python3
"""
Google OAuth Issue Diagnostic Script
Helps identify the root cause of Google Sign-In problems
"""

import os
import sys
import subprocess
import json
from urllib.parse import urlencode, quote_plus

def print_section(title):
    print(f"\n{'='*50}")
    print(f"📋 {title}")
    print('='*50)

def print_status(status, message):
    icon = "✅" if status else "❌"
    print(f"{icon} {message}")

def main():
    print("🔧 Google OAuth Issue Diagnostic Tool")
    print("====================================")
    
    # Read environment variables
    print_section("Environment Configuration")
    
    client_id = os.getenv('GOOGLE_CLIENT_ID', 'NOT_SET')
    client_secret = os.getenv('GOOGLE_CLIENT_SECRET', 'NOT_SET')
    base_url = os.getenv('BASE_URL', 'http://127.0.0.1:8000')
    
    print(f"Google Client ID: {client_id[:20]}..." if len(client_id) > 20 else f"Google Client ID: {client_id}")
    print(f"Client Secret: {'SET' if client_secret != 'NOT_SET' else 'NOT_SET'}")
    print(f"Base URL: {base_url}")
    
    # Check if Django is running
    print_section("Django Server Status")
    
    try:
        import requests
        response = requests.get(f"{base_url}/", timeout=5)
        print_status(True, f"Django server responding (Status: {response.status_code})")
    except Exception as e:
        print_status(False, f"Django server not accessible: {e}")
        return
    
    # Test API endpoints
    print_section("API Endpoints Test")
    
    endpoints = [
        ("/api/auth/login/google/", "Google ID Token endpoint"),
        ("/api/auth/login/google/oauth/", "Google OAuth code endpoint"), 
        ("/login/google-diagnostic/", "Diagnostic page")
    ]
    
    for endpoint, description in endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            if response.status_code < 500:
                print_status(True, f"{description} accessible")
            else:
                print_status(False, f"{description} server error ({response.status_code})")
        except Exception as e:
            print_status(False, f"{description} failed: {e}")
    
    # Generate proper OAuth URLs
    print_section("Google OAuth Configuration")
    
    if client_id == 'NOT_SET':
        print_status(False, "Google Client ID not configured")
        return
    
    # Test both localhost and 127.0.0.1
    domains = ['localhost:8000', '127.0.0.1:8000']
    
    for domain in domains:
        redirect_uri = f"http://{domain}/auth/google/callback"
        auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode({
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'openid email profile',
            'access_type': 'offline',
            'state': 'test123'
        })
        
        print(f"\n🔗 OAuth URL for {domain}:")
        print(f"   {auth_url[:100]}...")
        print(f"   Redirect URI: {redirect_uri}")
    
    # Browser compatibility check
    print_section("Browser Compatibility Recommendations")
    
    print("🌐 For testing Google OAuth:")
    print("   1. Use Chrome or Edge (best compatibility)")
    print("   2. Disable popup blockers for localhost")
    print("   3. Allow third-party cookies temporarily")
    print("   4. Clear browser cache if issues persist")
    
    # Quick fix suggestions
    print_section("Common Issues & Solutions")
    
    issues = [
        ("Popup blocked", "Disable popup blocker for localhost"),
        ("Third-party cookies disabled", "Enable in browser privacy settings"),
        ("Wrong redirect URI", "Check Google Console OAuth settings"),
        ("HTTPS required", "Google requires HTTPS for non-localhost domains"),
        ("CSRF errors", "Ensure Django CSRF settings are correct")
    ]
    
    for issue, solution in issues:
        print(f"🔸 {issue}: {solution}")
    
    # Google Console configuration check
    print_section("Google Cloud Console Setup")
    
    print("📝 Verify these settings in Google Cloud Console:")
    print(f"   1. Client ID: {client_id}")
    print("   2. Authorized JavaScript origins:")
    print("      - http://localhost:8000")
    print("      - http://127.0.0.1:8000")
    print("   3. Authorized redirect URIs:")
    print("      - http://localhost:8000/auth/google/callback")
    print("      - http://127.0.0.1:8000/auth/google/callback")
    
    # Test command
    print_section("Next Steps")
    
    print("🚀 To test the fix:")
    print("   1. Open: http://127.0.0.1:8000/login/google-diagnostic/")
    print("   2. Click 'Test One Tap' or 'Test Button Auth'")
    print("   3. Check browser console for detailed errors")
    print("   4. Try both popup and redirect methods")
    
    print("\n🔍 If issues persist, check:")
    print("   - Django logs in django.log")
    print("   - Browser developer console")
    print("   - Google Cloud Console OAuth settings")

if __name__ == "__main__":
    # Load .env file
    if os.path.exists('.env'):
        with open('.env', 'r') as f:
            for line in f:
                if '=' in line and not line.startswith('#'):
                    key, value = line.strip().split('=', 1)
                    os.environ[key] = value
    
    main()