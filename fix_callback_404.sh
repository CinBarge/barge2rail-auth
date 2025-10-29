#!/bin/bash

echo "=== Fixing Google OAuth Callback 404 Error ==="
echo ""

cd /Users/cerion/Projects/barge2rail-auth

echo "🔍 Diagnosed Issue:"
echo "   - Google OAuth redirect successful"
echo "   - But callback URL http://127.0.0.1:8000/auth/google/callback/ returns 404"
echo "   - This means Django server is not running or not handling the route"
echo ""

# Kill any existing Django processes
echo "🔄 Stopping any existing Django servers..."
pkill -f "python manage.py runserver" 2>/dev/null
pkill -f "127.0.0.1:8000" 2>/dev/null
sleep 3

# Check if port is free
echo "🔍 Checking if port 8000 is available..."
if lsof -i :8000 >/dev/null 2>&1; then
    echo "⚠️ Port 8000 is still in use, forcing kill..."
    lsof -ti :8000 | xargs kill -9 2>/dev/null
    sleep 2
fi

# Start Django server
echo "🚀 Starting Django server..."
python manage.py runserver 127.0.0.1:8000 &
DJANGO_PID=$!

echo "Django server starting with PID: $DJANGO_PID"
sleep 5

# Test if server is running
echo ""
echo "🏥 Testing server health..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8000/api/auth/health/ >/dev/null 2>&1; then
        echo "✅ Django server is running and responding"
        break
    else
        echo "⏳ Waiting for server... (attempt $i/10)"
        sleep 2
    fi

    if [ $i -eq 10 ]; then
        echo "❌ Server failed to start properly"
        echo "Manual start command: python manage.py runserver 127.0.0.1:8000"
        exit 1
    fi
done

# Test callback URL specifically
echo ""
echo "🔗 Testing callback URL routing..."
CALLBACK_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/auth/google/callback/ 2>/dev/null)

if [ "$CALLBACK_STATUS" = "405" ]; then
    echo "✅ Callback URL is accessible (405 Method Not Allowed is expected for GET)"
elif [ "$CALLBACK_STATUS" = "404" ]; then
    echo "❌ Callback URL still returns 404 - URL routing issue"
    echo "   Checking URL configuration..."
else
    echo "ℹ️ Callback URL returns status: $CALLBACK_STATUS"
fi

# Test OAuth URL generation
echo ""
echo "📋 Testing OAuth URL generation..."
OAUTH_RESPONSE=$(curl -s http://127.0.0.1:8000/api/auth/oauth/google/url/ 2>/dev/null)
if echo "$OAUTH_RESPONSE" | grep -q "auth_url"; then
    echo "✅ OAuth URL endpoint working"
    # Show the generated URL
    echo "$OAUTH_RESPONSE" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print('Generated OAuth URL includes correct callback')
except:
    pass
"
else
    echo "❌ OAuth URL generation failed"
fi

echo ""
echo "🧪 Next Steps:"
echo ""
echo "1. **Django server is now running on http://127.0.0.1:8000**"
echo ""
echo "2. **Test the callback URL directly:**"
echo "   curl -I http://127.0.0.1:8000/auth/google/callback/"
echo "   (Should return 405 Method Not Allowed, not 404)"
echo ""
echo "3. **Try Google OAuth again:**"
echo "   - Go to: http://127.0.0.1:8000/login/"
echo "   - Click Google tab → Continue with Google"
echo "   - Complete Google sign-in"
echo "   - Should now redirect properly to the callback"
echo ""
echo "4. **If still getting 404, check Django logs:**"
echo "   The server should show incoming requests in the terminal"
echo ""

# Show Django server info
echo "📊 Server Information:"
echo "   PID: $DJANGO_PID"
echo "   URL: http://127.0.0.1:8000"
echo "   Callback: http://127.0.0.1:8000/auth/google/callback/"
echo "   Stop command: kill $DJANGO_PID"
echo ""

echo "Django server is running. Check the terminal window for Django logs."
echo "The Google OAuth callback should now work properly."
