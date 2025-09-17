#!/bin/bash

echo "=== Testing Django Callback URL ==="
echo ""

cd /Users/cerion/Projects/barge2rail-auth

# Test the callback URL directly
echo "Testing callback URL routing..."
echo ""

# Test with curl to see exact response
echo "1. Testing GET request to callback:"
curl -v http://127.0.0.1:8000/auth/google/callback/ 2>&1 | grep -E "(HTTP|< |> )"

echo ""
echo "2. Testing with query parameters (simulating Google redirect):"
curl -v "http://127.0.0.1:8000/auth/google/callback/?code=test123&state=test" 2>&1 | grep -E "(HTTP|< |> )"

echo ""
echo "3. Testing Django URL patterns:"
python3 manage.py show_urls | grep -i callback || echo "show_urls command not available"

echo ""
echo "4. Manual URL pattern check:"
echo "Expected routing:"
echo "  core/urls.py: path('auth/', include('sso.urls'))"
echo "  sso/urls.py:  path('google/callback/', views.google_auth_callback)"
echo "  Should match: /auth/google/callback/"
echo ""

# Check if the view function exists
python3 -c "
import sys
sys.path.append('.')
try:
    from sso.views import google_auth_callback
    print('✅ google_auth_callback view function exists')
except ImportError as e:
    print('❌ google_auth_callback view function missing:', e)
"

echo ""
echo "Quick Fix Test:"
echo "Try manually accessing these URLs in browser:"
echo "- http://127.0.0.1:8000/api/auth/google/callback/ (API version)"
echo "- http://127.0.0.1:8000/auth/google/callback/ (should be the working one)"
echo ""
