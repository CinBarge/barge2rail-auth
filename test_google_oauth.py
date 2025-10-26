#!/usr/bin/env python3
"""
Google OAuth Testing Script for Barge2Rail SSO
Tests only Google OAuth flow - ignores email/username authentication.

Tests:
1. Token verification
2. Token refresh
3. User profile (with token)
4. Logout/Token blacklist

Usage:
1. Start server: python manage.py runserver
2. Login via Google at: http://localhost:8000/api/auth/login/google/
3. Copy access_token and refresh_token from redirect
4. Run this script with tokens as arguments:
   python test_google_oauth.py ACCESS_TOKEN REFRESH_TOKEN
"""

import sys
import requests
import json
import time
from datetime import datetime
from typing import Dict, Any, Tuple

# Test configuration
BASE_URL = "http://localhost:8000"
ENDPOINTS = {
    'verify': f'{BASE_URL}/api/auth/validate/',
    'refresh': f'{BASE_URL}/api/auth/refresh/',
    'profile': f'{BASE_URL}/api/auth/me/',
    'logout': f'{BASE_URL}/api/auth/logout/',
}

# ANSI color codes for terminal output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'


class TestResult:
    """Track test results"""
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.message = ""
        self.details = {}

    def success(self, message: str, details: Dict = None):
        self.passed = True
        self.message = message
        self.details = details or {}

    def failure(self, message: str, details: Dict = None):
        self.passed = False
        self.message = message
        self.details = details or {}


class GoogleOAuthTester:
    """Test Google OAuth token lifecycle"""

    def __init__(self, access_token: str, refresh_token: str):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.results = []

    def print_header(self, text: str):
        """Print section header"""
        print(f"\n{BLUE}{'=' * 80}{RESET}")
        print(f"{BLUE}{text:^80}{RESET}")
        print(f"{BLUE}{'=' * 80}{RESET}\n")

    def print_result(self, result: TestResult):
        """Print test result"""
        status = f"{GREEN}✅ PASS{RESET}" if result.passed else f"{RED}❌ FAIL{RESET}"
        print(f"{status} - {result.name}")
        print(f"  {result.message}")
        if result.details:
            print(f"  Details: {json.dumps(result.details, indent=4)}")
        print()

    def test_token_verification(self) -> TestResult:
        """Test 1: Token Verification Endpoint"""
        result = TestResult("Token Verification")

        try:
            response = requests.post(
                ENDPOINTS['verify'],
                json={'token': self.access_token},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('valid'):
                    user = data.get('user', {})
                    result.success(
                        "Access token is valid",
                        {
                            'email': user.get('email'),
                            'auth_type': user.get('auth_type'),
                            'is_sso_admin': user.get('is_sso_admin'),
                            'claims': data.get('claims', {})
                        }
                    )
                else:
                    result.failure("Token marked as invalid", data)
            else:
                result.failure(
                    f"Unexpected status code: {response.status_code}",
                    {'response': response.text}
                )

        except Exception as e:
            result.failure(f"Exception: {str(e)}")

        return result

    def test_token_refresh(self) -> Tuple[TestResult, str, str]:
        """Test 2: Token Refresh Endpoint"""
        result = TestResult("Token Refresh")
        new_access = None
        new_refresh = None

        try:
            response = requests.post(
                ENDPOINTS['refresh'],
                json={'refresh': self.refresh_token},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                new_access = data.get('access')
                new_refresh = data.get('refresh')

                if new_access and new_refresh:
                    result.success(
                        "Refresh token successfully generated new tokens",
                        {
                            'new_access_token_prefix': new_access[:20] + '...',
                            'new_refresh_token_prefix': new_refresh[:20] + '...',
                            'access_token_changed': new_access != self.access_token,
                            'refresh_token_changed': new_refresh != self.refresh_token
                        }
                    )
                else:
                    result.failure("Response missing tokens", data)
            else:
                result.failure(
                    f"Unexpected status code: {response.status_code}",
                    {'response': response.text}
                )

        except Exception as e:
            result.failure(f"Exception: {str(e)}")

        return result, new_access, new_refresh

    def test_user_profile(self, token: str = None) -> TestResult:
        """Test 3: User Profile Endpoint"""
        result = TestResult("User Profile (Authenticated)")
        token_to_use = token or self.access_token

        try:
            response = requests.get(
                ENDPOINTS['profile'],
                headers={'Authorization': f'Bearer {token_to_use}'}
            )

            if response.status_code == 200:
                data = response.json()
                result.success(
                    "Successfully retrieved user profile",
                    {
                        'email': data.get('email'),
                        'display_name': data.get('display_name'),
                        'auth_type': data.get('auth_type'),
                        'is_sso_admin': data.get('is_sso_admin'),
                        'roles': data.get('roles', {})
                    }
                )
            elif response.status_code == 401:
                result.failure("Unauthorized - token invalid or expired", {'response': response.text})
            else:
                result.failure(
                    f"Unexpected status code: {response.status_code}",
                    {'response': response.text}
                )

        except Exception as e:
            result.failure(f"Exception: {str(e)}")

        return result

    def test_logout(self, refresh_token: str = None) -> TestResult:
        """Test 4: Logout/Token Blacklist Endpoint"""
        result = TestResult("Logout/Token Blacklist")
        token_to_blacklist = refresh_token or self.refresh_token

        try:
            response = requests.post(
                ENDPOINTS['logout'],
                json={'refresh': token_to_blacklist},
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {self.access_token}'
                }
            )

            if response.status_code == 200:
                data = response.json()
                result.success(
                    "Successfully logged out and blacklisted token",
                    {'message': data.get('message')}
                )
            else:
                result.failure(
                    f"Unexpected status code: {response.status_code}",
                    {'response': response.text}
                )

        except Exception as e:
            result.failure(f"Exception: {str(e)}")

        return result

    def test_blacklisted_token(self, blacklisted_token: str) -> TestResult:
        """Test 5: Verify blacklisted token cannot be used"""
        result = TestResult("Blacklisted Token Rejection")

        try:
            response = requests.post(
                ENDPOINTS['refresh'],
                json={'refresh': blacklisted_token},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 401 or response.status_code == 400:
                result.success(
                    "Blacklisted token correctly rejected",
                    {'status_code': response.status_code}
                )
            elif response.status_code == 200:
                result.failure("ERROR: Blacklisted token was accepted!", response.json())
            else:
                result.failure(
                    f"Unexpected status code: {response.status_code}",
                    {'response': response.text}
                )

        except Exception as e:
            result.failure(f"Exception: {str(e)}")

        return result

    def test_token_expiry_behavior(self) -> TestResult:
        """Test 6: Token expiry timing (15 minutes for access tokens)"""
        result = TestResult("Token Expiry Configuration")

        try:
            # Verify token to get expiry claims
            response = requests.post(
                ENDPOINTS['verify'],
                json={'token': self.access_token},
                headers={'Content-Type': 'application/json'}
            )

            if response.status_code == 200:
                data = response.json()
                claims = data.get('claims', {})

                # Check if exp and iat are present
                exp = claims.get('exp')
                iat = claims.get('iat')

                if exp and iat:
                    lifetime_seconds = exp - iat
                    lifetime_minutes = lifetime_seconds / 60

                    # Access tokens should be 15 minutes
                    if 14 <= lifetime_minutes <= 16:  # Allow small variance
                        result.success(
                            f"Token expiry correctly configured: {lifetime_minutes:.1f} minutes",
                            {
                                'lifetime_minutes': lifetime_minutes,
                                'issued_at': datetime.fromtimestamp(iat).isoformat(),
                                'expires_at': datetime.fromtimestamp(exp).isoformat()
                            }
                        )
                    else:
                        result.failure(
                            f"Token lifetime is {lifetime_minutes:.1f} minutes (expected ~15 minutes)",
                            {'lifetime_minutes': lifetime_minutes}
                        )
                else:
                    result.failure("Token missing exp or iat claims", claims)
            else:
                result.failure(f"Could not verify token: {response.status_code}")

        except Exception as e:
            result.failure(f"Exception: {str(e)}")

        return result

    def run_all_tests(self):
        """Run all tests in sequence"""
        self.print_header("GOOGLE OAUTH TOKEN TESTING")

        print(f"Testing Google OAuth endpoints at: {BASE_URL}")
        print(f"Access Token (first 30 chars): {self.access_token[:30]}...")
        print(f"Refresh Token (first 30 chars): {self.refresh_token[:30]}...")

        # Test 1: Token Verification
        self.print_header("TEST 1: Token Verification")
        test1 = self.test_token_verification()
        self.results.append(test1)
        self.print_result(test1)

        # Test 2: Token Expiry Configuration
        self.print_header("TEST 2: Token Expiry Configuration")
        test2 = self.test_token_expiry_behavior()
        self.results.append(test2)
        self.print_result(test2)

        # Test 3: User Profile with Access Token
        self.print_header("TEST 3: User Profile (with access token)")
        test3 = self.test_user_profile()
        self.results.append(test3)
        self.print_result(test3)

        # Test 4: Token Refresh
        self.print_header("TEST 4: Token Refresh")
        test4, new_access, new_refresh = self.test_token_refresh()
        self.results.append(test4)
        self.print_result(test4)

        # Test 5: User Profile with New Token (if refresh succeeded)
        if test4.passed and new_access:
            self.print_header("TEST 5: User Profile (with refreshed token)")
            test5 = self.test_user_profile(token=new_access)
            self.results.append(test5)
            self.print_result(test5)

            # Update access token for logout test
            self.access_token = new_access

        # Test 6: Logout/Blacklist
        self.print_header("TEST 6: Logout and Blacklist Token")
        test6 = self.test_logout(refresh_token=new_refresh if new_refresh else None)
        self.results.append(test6)
        self.print_result(test6)

        # Test 7: Verify Blacklisted Token Rejected
        if test6.passed:
            self.print_header("TEST 7: Blacklisted Token Rejection")
            blacklisted = new_refresh if new_refresh else self.refresh_token
            test7 = self.test_blacklisted_token(blacklisted)
            self.results.append(test7)
            self.print_result(test7)

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print test summary"""
        self.print_header("TEST SUMMARY")

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        print(f"Total Tests: {total}")
        print(f"{GREEN}Passed: {passed}{RESET}")
        print(f"{RED}Failed: {failed}{RESET}")
        print(f"Pass Rate: {(passed/total*100):.1f}%\n")

        if failed > 0:
            print(f"{RED}Failed Tests:{RESET}")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name}: {r.message}")
        else:
            print(f"{GREEN}✅ ALL TESTS PASSED{RESET}")

        print("\n" + "=" * 80)
        print(f"{GREEN if failed == 0 else RED}Google OAuth: {'WORKING' if failed == 0 else 'NEEDS ATTENTION'}{RESET}")
        print("=" * 80 + "\n")


def print_usage():
    """Print usage instructions"""
    print(f"""
{BLUE}Google OAuth Testing Script{RESET}

{YELLOW}STEP 1: Get Tokens from Manual Google Login{RESET}
-------------------------------------------------
1. Start your Django server:
   $ python manage.py runserver

2. Open browser and navigate to:
   http://localhost:8000/api/auth/login/google/

3. Sign in with your Google account

4. After successful login, you'll be redirected to a URL like:
   http://localhost:8000/login/google-success/?access_token=XXX&refresh_token=YYY

5. Copy the access_token and refresh_token from the URL

{YELLOW}STEP 2: Run This Test Script{RESET}
------------------------------------
$ python test_google_oauth.py <ACCESS_TOKEN> <REFRESH_TOKEN>

Example:
$ python test_google_oauth.py eyJ0eXAiOiJKV1QiLCJhbGc... eyJ0eXAiOiJKV1QiLCJhbGc...

{YELLOW}What This Script Tests:{RESET}
-----------------------
✓ Token verification endpoint
✓ Token expiry configuration (15 minutes)
✓ User profile endpoint with token
✓ Token refresh endpoint
✓ Logout/token blacklist endpoint
✓ Blacklisted token rejection

{RED}What This Script Ignores:{RESET}
------------------------
✗ Email registration/login
✗ Username/password authentication
✗ Anonymous authentication

{GREEN}This is Google OAuth ONLY testing{RESET}
""")


def main():
    """Main entry point"""
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(1)

    access_token = sys.argv[1]
    refresh_token = sys.argv[2]

    # Basic validation
    if not access_token or not refresh_token:
        print(f"{RED}Error: Both access_token and refresh_token are required{RESET}")
        print_usage()
        sys.exit(1)

    # Run tests
    tester = GoogleOAuthTester(access_token, refresh_token)
    tester.run_all_tests()

    # Exit with appropriate code
    failed = sum(1 for r in tester.results if not r.passed)
    sys.exit(0 if failed == 0 else 1)


if __name__ == '__main__':
    main()
