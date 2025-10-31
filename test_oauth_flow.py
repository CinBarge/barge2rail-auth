#!/usr/bin/env python3
"""
Test the complete OAuth flow:
1. PrimeTrade redirects to SSO authorize endpoint
2. SSO redirects to login form
3. User logs in
4. SSO redirects back to PrimeTrade with auth code
5. PrimeTrade exchanges code for tokens
"""

from urllib.parse import parse_qs, urlparse

import requests

# Configuration
SSO_BASE = "http://127.0.0.1:8000"
PRIMETRADE_BASE = "http://127.0.0.1:8002"
CLIENT_ID = "primetrade_client"
# Test client secret - pragma: allowlist secret
CLIENT_SECRET = "Kyq6_cHugJLcWyYuP1K1JSf-eF59y0OHT6IJ7tMet4U"  # noqa: E501
REDIRECT_URI = f"{PRIMETRADE_BASE}/auth/callback/"

# Test credentials
USERNAME = "testuser"
PASSWORD = "testpass123"  # pragma: allowlist secret

print("=" * 60)
print("OAUTH FLOW TEST")
print("=" * 60)

# Create session to maintain cookies
session = requests.Session()

# Step 1: PrimeTrade initiates OAuth flow
print("\n[Step 1] PrimeTrade initiates OAuth to SSO authorize endpoint")
authorize_url = f"{SSO_BASE}/auth/authorize/"
params = {
    "client_id": CLIENT_ID,
    "redirect_uri": REDIRECT_URI,
    "response_type": "code",
    "scope": "openid email profile",
    "state": "test_state_123",
}

response = session.get(authorize_url, params=params, allow_redirects=False)
print(f"Status: {response.status_code}")
print(f"Response: {response.text[:200]}...")

# Step 2: Should redirect to login page
if response.status_code == 302:
    login_url = response.headers.get("Location")
    print(f"\n[Step 2] Redirected to: {login_url}")

    # Follow redirect to login page
    full_login_url = (
        login_url if login_url.startswith("http") else f"{SSO_BASE}{login_url}"
    )
    response = session.get(full_login_url)
    print(f"Login page status: {response.status_code}")

    # Extract CSRF token
    csrf_token = None
    for line in response.text.split("\n"):
        if "csrfmiddlewaretoken" in line:
            # Simple extraction (not robust but works for testing)
            import re

            match = re.search(r'value="([^"]+)"', line)
            if match:
                csrf_token = match.group(1)
                break

    if not csrf_token:
        print("ERROR: Could not find CSRF token")
        exit(1)

    print(f"Got CSRF token: {csrf_token[:20]}...")

    # Step 3: Submit login form
    print(f"\n[Step 3] Submitting login form")
    login_post_url = f"{SSO_BASE}/auth/web/login/"

    # Get the 'next' parameter from the URL
    parsed = urlparse(full_login_url)
    next_param = parse_qs(parsed.query).get("next", [""])[0]
    print(f"Next parameter: {next_param}")

    login_data = {
        "csrfmiddlewaretoken": csrf_token,
        "identifier": USERNAME,
        "password": PASSWORD,
        "next": next_param,
    }

    response = session.post(login_post_url, data=login_data, allow_redirects=False)
    print(f"Login POST status: {response.status_code}")

    # Step 4: Should redirect back to /auth/authorize/
    if response.status_code == 302:
        authorize_redirect = response.headers.get("Location")
        print(f"\n[Step 4] Login successful, redirected to: {authorize_redirect}")

        # Follow redirect to authorize endpoint (now authenticated)
        full_authorize_url = (
            authorize_redirect
            if authorize_redirect.startswith("http")
            else f"{SSO_BASE}{authorize_redirect}"
        )
        response = session.get(full_authorize_url, allow_redirects=False)
        print(f"Authorize status: {response.status_code}")

        # Step 5: Should redirect back to PrimeTrade with auth code
        if response.status_code == 302:
            callback_url = response.headers.get("Location")
            print(f"\n[Step 5] SSO redirects to PrimeTrade callback: {callback_url}")

            # Extract auth code and state
            parsed = urlparse(callback_url)
            query_params = parse_qs(parsed.query)
            auth_code = query_params.get("code", [None])[0]
            state = query_params.get("state", [None])[0]

            if auth_code:
                print(f"✅ Got authorization code: {auth_code[:20]}...")
                print(f"✅ State: {state}")

                # Step 6: Exchange code for tokens
                print(f"\n[Step 6] PrimeTrade exchanges code for tokens")
                token_url = f"{SSO_BASE}/auth/token/"
                token_data = {
                    "code": auth_code,
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "redirect_uri": REDIRECT_URI,
                    "grant_type": "authorization_code",
                }

                response = requests.post(token_url, data=token_data)
                print(f"Token exchange status: {response.status_code}")

                if response.status_code == 200:
                    tokens = response.json()
                    print(f"✅ SUCCESS! Got tokens:")
                    print(f"   Access token: {tokens.get('access_token', '')[:30]}...")
                    print(
                        f"   Refresh token: {tokens.get('refresh_token', '')[:30]}..."
                    )
                    print(f"   User: {tokens.get('user', {}).get('email')}")
                    print("\n" + "=" * 60)
                    print("OAUTH FLOW COMPLETE ✅")
                    print("=" * 60)
                else:
                    print(f"❌ Token exchange failed: {response.text}")
            else:
                print(f"❌ No authorization code in callback URL")
        else:
            print(f"❌ Expected redirect to PrimeTrade, got: {response.status_code}")
            print(f"Response: {response.text[:500]}")
    else:
        print(f"❌ Login failed: {response.status_code}")
        print(f"Response: {response.text[:500]}")
else:
    print(f"❌ Expected redirect to login, got: {response.status_code}")
    print(f"Response: {response.text[:500]}")
