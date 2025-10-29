#!/bin/bash

# CORS Fix Validation Script
# Tests CORS headers and cross-origin API access

echo "🔧 CORS Configuration Validation"
echo "================================="
echo ""

# Test production endpoint with CORS headers
echo "🌐 Testing CORS headers on production API:"
echo ""

# Test the OAuth URL endpoint with CORS
echo "1️⃣  Testing: GET /api/auth/oauth/google/url/ with CORS headers"
curl -v -H "Origin: https://sso.barge2rail.com" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: Content-Type" \
     "https://sso.barge2rail.com/api/auth/oauth/google/url/" \
     2>&1 | grep -E "(Access-Control|HTTP/|origin)"

echo ""
echo ""

# Test preflight OPTIONS request
echo "2️⃣  Testing: OPTIONS preflight request"
curl -v -X OPTIONS \
     -H "Origin: https://sso.barge2rail.com" \
     -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: Content-Type" \
     "https://sso.barge2rail.com/api/auth/oauth/google/url/" \
     2>&1 | grep -E "(Access-Control|HTTP/|Allow|origin)"

echo ""
echo ""

# Simple GET request to verify endpoint works
echo "3️⃣  Testing: Simple GET request (should work)"
RESPONSE=$(curl -s "https://sso.barge2rail.com/api/auth/oauth/google/url/")
if echo "$RESPONSE" | grep -q "auth_url"; then
    echo "   ✅ SUCCESS: API endpoint working"
    echo "   📄 Response preview: $(echo "$RESPONSE" | cut -c1-100)..."
else
    echo "   ❌ FAILED: API endpoint not working"
    echo "   📄 Response: $RESPONSE"
fi

echo ""
echo "🏁 CORS Validation Complete!"
echo ""
echo "📊 Expected after deployment:"
echo "✅ CORS headers should include: Access-Control-Allow-Origin: https://sso.barge2rail.com"
echo "✅ OPTIONS preflight requests should be handled"
echo "✅ Frontend JavaScript should be able to fetch API responses"
echo ""
