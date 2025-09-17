#!/bin/bash

echo "=== Complete Google OAuth Implementation Verification ==="
echo ""

cd /Users/cerion/Projects/barge2rail-auth

# Check if all required files exist
echo "📁 Checking implementation files..."
FILES=(
    "sso/views.py"
    "sso/urls.py"
    "templates/login.html"
    "core/urls.py"
    ".env"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists"
    else
        echo "❌ $file missing"
    fi
done

# Check Django configuration
echo ""
echo "⚙️ Checking Django configuration..."
python manage.py check --deploy 2>&1 | head -10

# Check migrations
echo ""
echo "🗄️ Checking database migrations..."
python manage.py showmigrations

# Check if Google OAuth imports work
echo ""
echo "📦 Testing Google OAuth imports..."
python -c "
try:
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    print('✅ Google OAuth libraries imported successfully')
except ImportError as e:
    print(f'❌ Google OAuth import error: {e}')
    print('Run: pip install google-auth')
"

# Check environment variables
echo ""
echo "🔧 Checking environment variables..."
python -c "
from decouple import config
import os

client_id = config('GOOGLE_CLIENT_ID', default='')
client_secret = config('GOOGLE_CLIENT_SECRET', default='')
base_url = config('BASE_URL', default='')

print(f'GOOGLE_CLIENT_ID: {\"✅ Set\" if client_id else \"❌ Not set\"}')
print(f'GOOGLE_CLIENT_SECRET: {\"✅ Set\" if client_secret else \"❌ Not set\"}')
print(f'BASE_URL: {base_url}')

if client_id:
    print(f'Client ID: {client_id[:20]}...{client_id[-20:]}')
"

# Start Django and test
echo ""
echo "🚀 Starting Django server for testing..."
python manage.py runserver 127.0.0.1:8000 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait and test
sleep 8

echo ""
echo "🧪 Testing endpoints..."

# Test health
curl -s http://127.0.0.1:8000/api/auth/health/ | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print('✅ Health check:', data.get('status', 'unknown'))
except:
    print('❌ Health check failed')
"

# Test Google config
curl -s http://127.0.0.1:8000/api/auth/config/google/ | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print('📋 Google Config:')
    for key, value in data.items():
        print(f'   {key}: {value}')
except Exception as e:
    print(f'❌ Config check failed: {e}')
"

echo ""
echo "🌐 Browser test instructions:"
echo "1. Open: http://127.0.0.1:8000/login/"
echo "2. Click Google tab"
echo "3. Click 'Continue with Google'"
echo "4. Should redirect to Google (no deleted_client error)"
echo ""
echo "To stop server: kill $SERVER_PID"

# Keep server running for manual testing
echo "Server running... Press Ctrl+C to stop"
wait $SERVER_PID
