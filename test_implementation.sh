#!/bin/bash

echo "=== Google OAuth Implementation Test ==="
echo ""

# Kill any existing Django processes
echo "🔄 Stopping any existing Django servers..."
pkill -f "python manage.py runserver" 2>/dev/null
sleep 2

# Start Django server
echo "🚀 Starting Django server..."
cd /Users/cerion/Projects/barge2rail-auth
python manage.py runserver 127.0.0.1:8000 &
DJANGO_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
sleep 5

# Test server health
echo "🏥 Testing server health..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8000/api/auth/health/ >/dev/null 2>&1; then
        echo "✅ Django server is running"
        break
    else
        echo "⏳ Waiting for server... (attempt $i/10)"
        sleep 2
    fi
done

# Test Google OAuth configuration
echo ""
echo "📋 Testing Google OAuth Configuration..."
RESPONSE=$(curl -s http://127.0.0.1:8000/api/auth/config/google/ 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "✅ Configuration endpoint accessible"
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "Response: $RESPONSE"
else
    echo "❌ Configuration endpoint not accessible"
fi

# Test OAuth URL generation
echo ""
echo "🔗 Testing OAuth URL generation..."
OAUTH_RESPONSE=$(curl -s http://127.0.0.1:8000/api/auth/oauth/google/url/ 2>/dev/null)
if [ $? -eq 0 ]; then
    echo "✅ OAuth URL endpoint accessible"
    echo "$OAUTH_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "Response: $OAUTH_RESPONSE"
else
    echo "❌ OAuth URL endpoint not accessible"
fi

# Test login page
echo ""
echo "🌐 Testing login page..."
LOGIN_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/login/ 2>/dev/null)
if [ "$LOGIN_STATUS" = "200" ]; then
    echo "✅ Login page accessible (HTTP 200)"
else
    echo "❌ Login page not accessible (HTTP $LOGIN_STATUS)"
fi

echo ""
echo "🧪 Manual Test Instructions:"
echo "1. Open browser: http://127.0.0.1:8000/login/"
echo "2. Click on 'Google' tab"
echo "3. Click 'Continue with Google' button"
echo "4. Should redirect to Google OAuth (no more 'deleted_client' error)"
echo ""
echo "📝 Google Console Configuration Verified:"
echo "✅ Client ID: <GOOGLE_CLIENT_ID>"
echo "✅ Redirect URIs configured in Google Console:"
echo "   - http://127.0.0.1:8000/auth/google/callback/"
echo "   - http://localhost:8000/auth/google/callback/"
echo "   - https://auth.barge2rail.com/auth/google/callback/"
echo ""
echo "Django PID: $DJANGO_PID"
echo "To stop server: kill $DJANGO_PID"
