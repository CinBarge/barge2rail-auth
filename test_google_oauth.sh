#!/bin/bash

echo "=== Testing Google OAuth Implementation ==="
echo ""

# Test if Django server is running
echo "🔍 Testing Django server..."
SERVER_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/api/auth/health/ 2>/dev/null)

if [ "$SERVER_STATUS" = "200" ]; then
    echo "✅ Django server is running"
else
    echo "❌ Django server not responding (HTTP $SERVER_STATUS)"
    echo "🔄 Starting Django server..."
    cd /Users/cerion/Projects/barge2rail-auth
    python manage.py runserver &
    sleep 3
fi

echo ""
echo "📋 Current Google OAuth Configuration:"
curl -s http://127.0.0.1:8000/api/auth/config/google/ | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(f'✅ Client ID configured: {data.get(\"google_client_id\", False)}')
    print(f'✅ Client Secret configured: {data.get(\"google_client_secret\", False)}')
    print(f'🔗 Base URL: {data.get(\"base_url\", \"Not set\")}')
    print(f'🔗 Redirect URI: {data.get(\"redirect_uri\", \"Not set\")}')
    print(f'🎯 Fully configured: {data.get(\"fully_configured\", False)}')
except:
    print('❌ Could not parse configuration response')
"

echo ""
echo "🔗 Testing OAuth URL generation:"
curl -s http://127.0.0.1:8000/api/auth/oauth/google/url/ | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'auth_url' in data:
        print('✅ OAuth URL generated successfully')
        print(f'🔗 URL: {data[\"auth_url\"][:100]}...')
    else:
        print('❌ Failed to generate OAuth URL')
        print(f'Error: {data}')
except Exception as e:
    print(f'❌ Error parsing OAuth URL response: {e}')
"

echo ""
echo "🧪 Manual Test Steps:"
echo "1. Visit: http://127.0.0.1:8000/login/"
echo "2. Click Google tab"
echo "3. Click 'Continue with Google'"
echo ""
echo "📝 Next Steps if Google OAuth fails:"
echo "1. Create new Google Cloud Console project"
echo "2. Enable Google+ API and OAuth2 API"
echo "3. Create OAuth 2.0 Client ID (Web application)"
echo "4. Add redirect URI: http://127.0.0.1:8000/auth/google/callback/"
echo "5. Update .env with new CLIENT_ID and CLIENT_SECRET"
echo "6. Run: ./setup_google_oauth.sh restart"
