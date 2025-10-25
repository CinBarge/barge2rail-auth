#!/usr/bin/env python
"""
Test OAuth Flow Step by Step
"""
import requests
import secrets
from urllib.parse import urlencode, parse_qs, urlparse

# Configuration
SSO_BASE_URL = "https://sso.barge2rail.com"
CLIENT_ID = "app_0b97b7b94d192797"
CLIENT_SECRET = "Kyq6_cHugJLcWyYuP1K1JSf-eF59y0OHT6IJ7tMet4U"
REDIRECT_URI = "http://127.0.0.1:8001/auth/callback/"

print("=" * 60)
print("OAuth Flow Test Script")
print("=" * 60)

# Step 1: Generate authorization URL
print("\n1. Authorization URL Generation")
print("-" * 40)

state = secrets.token_urlsafe(32)
params = {
    'response_type': 'code',
    'client_id': CLIENT_ID,
    'redirect_uri': REDIRECT_URI,
    'scope': 'openid email profile',
    'state': state
}

auth_url = f"{SSO_BASE_URL}/auth/authorize/?{urlencode(params)}"
print(f"Generated authorization URL:")
print(auth_url)
print(f"\nState: {state}")

print("\n" + "=" * 60)
print("MANUAL STEPS REQUIRED:")
print("=" * 60)
print("\n1. Open a browser in INCOGNITO/PRIVATE mode")
print("2. Copy and paste this URL:")
print(f"\n{auth_url}\n")
print("3. You should be redirected to Google login")
print("4. After logging in, you should be redirected to:")
print(f"   {REDIRECT_URI}?code=XXX&state={state}")
print("\n5. Copy the FULL redirect URL and paste it here:")
print("=" * 60)

# Wait for user input
redirect_url = input("\nPaste the redirect URL here: ").strip()

if not redirect_url:
    print("No URL provided. Exiting.")
    exit(1)

# Parse the redirect URL
parsed = urlparse(redirect_url)
params = parse_qs(parsed.query)

if 'code' not in params:
    print(f"❌ No authorization code in URL. Got: {redirect_url}")
    exit(1)

if 'state' not in params:
    print(f"❌ No state parameter in URL. Got: {redirect_url}")
    exit(1)

auth_code = params['code'][0]
returned_state = params['state'][0]

print(f"\n✅ Authorization code received: {auth_code[:20]}...")
print(f"✅ State parameter: {'MATCHES' if returned_state == state else 'MISMATCH'}")

if returned_state != state:
    print(f"   Expected: {state}")
    print(f"   Got: {returned_state}")

# Step 2: Exchange code for tokens
print("\n2. Token Exchange")
print("-" * 40)

token_data = {
    'grant_type': 'authorization_code',
    'code': auth_code,
    'redirect_uri': REDIRECT_URI,
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET
}

print(f"Exchanging code for tokens...")
response = requests.post(
    f"{SSO_BASE_URL}/auth/token/",
    data=token_data,
    headers={'Content-Type': 'application/x-www-form-urlencoded'}
)

if response.status_code == 200:
    tokens = response.json()
    print("✅ Token exchange successful!")
    print(f"\nAccess token: {tokens.get('access_token', '')[:50]}...")
    print(f"Refresh token: {tokens.get('refresh_token', '')[:50]}...")
    
    if 'user' in tokens:
        user = tokens['user']
        print(f"\nUser data:")
        print(f"  Email: {user.get('email')}")
        print(f"  Display name: {user.get('display_name')}")
        print(f"  Roles: {user.get('roles', {})}")
        
    # Step 3: Test authenticated request
    print("\n3. Testing Authenticated Request")
    print("-" * 40)
    
    access_token = tokens.get('access_token')
    if access_token:
        me_response = requests.get(
            f"{SSO_BASE_URL}/auth/me/",
            headers={'Authorization': f'Bearer {access_token}'}
        )
        
        if me_response.status_code == 200:
            print("✅ Authenticated request successful!")
            print(f"User info: {me_response.json()}")
        else:
            print(f"❌ Authenticated request failed: {me_response.status_code}")
            print(f"Response: {me_response.text}")
else:
    print(f"❌ Token exchange failed: {response.status_code}")
    print(f"Response: {response.text}")

print("\n" + "=" * 60)
print("OAuth Flow Test Complete!")
print("=" * 60)
