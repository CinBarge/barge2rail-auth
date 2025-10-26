#!/bin/bash

# Test Django SSO Deployment
# Run this after deploying to verify everything works

echo "🔍 Testing Django SSO Deployment..."
echo "================================"

# Set the base URL (change to production when ready)
if [ "$1" == "prod" ]; then
    BASE_URL="https://sso.barge2rail.com"
    echo "Testing PRODUCTION: $BASE_URL"
else
    BASE_URL="http://localhost:8000"
    echo "Testing LOCAL: $BASE_URL"
    echo "(Use './test_deployment.sh prod' for production)"
fi

echo ""

# Test 1: Health Check
echo "1. Testing Health Check..."
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/api/auth/health/)
if [ "$HEALTH" == "200" ]; then
    echo "   ✅ Health check passed"
else
    echo "   ❌ Health check failed (HTTP $HEALTH)"
fi

# Test 2: Google OAuth Config
echo ""
echo "2. Testing Google OAuth Configuration..."
GOOGLE_CONFIG=$(curl -s $BASE_URL/api/auth/google/config/)
echo "   Response: $GOOGLE_CONFIG"
if echo "$GOOGLE_CONFIG" | grep -q "fully_configured.*true"; then
    echo "   ✅ Google OAuth configured"
else
    echo "   ⚠️  Google OAuth not fully configured"
    echo "   Make sure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set"
fi

# Test 3: Google OAuth URL Generation
echo ""
echo "3. Testing OAuth URL Generation..."
OAUTH_URL=$(curl -s $BASE_URL/api/auth/login/google/)
if echo "$OAUTH_URL" | grep -q "auth_url"; then
    echo "   ✅ OAuth URL generated successfully"
else
    echo "   ❌ OAuth URL generation failed"
fi

# Test 4: CORS Headers (for frontend integration)
echo ""
echo "4. Testing CORS Headers..."
CORS_TEST=$(curl -s -I -X OPTIONS \
    -H "Origin: http://localhost:3000" \
    -H "Access-Control-Request-Method: POST" \
    $BASE_URL/api/auth/login/email/ 2>/dev/null | grep -i "access-control")
if [ -n "$CORS_TEST" ]; then
    echo "   ✅ CORS headers present"
    echo "   $CORS_TEST"
else
    echo "   ⚠️  CORS headers may not be configured"
fi

# Test 5: Static Files
echo ""
echo "5. Testing Static Files..."
STATIC_TEST=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/static/admin/css/base.css)
if [ "$STATIC_TEST" == "200" ] || [ "$STATIC_TEST" == "304" ]; then
    echo "   ✅ Static files serving correctly"
else
    echo "   ⚠️  Static files may not be configured (HTTP $STATIC_TEST)"
fi

echo ""
echo "================================"
echo "Deployment Test Complete!"
echo ""
echo "Next steps:"
echo "1. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render"
echo "2. Configure custom domain (sso.barge2rail.com)"
echo "3. Test actual Google login flow"
echo "4. Create admin user and applications"
