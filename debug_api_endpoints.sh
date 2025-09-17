#!/bin/bash

echo "=== Debugging Django API Endpoint Issues ==="
echo ""

cd /Users/cerion/Projects/barge2rail-auth

# Check if Django server is running
echo "🔍 Checking if Django server is running..."
if ps aux | grep -v grep | grep "python manage.py runserver" > /dev/null; then
    echo "✅ Django process found"
    ps aux | grep -v grep | grep "python manage.py runserver"
else
    echo "❌ No Django server process running"
fi

# Check port 8000
echo ""
echo "🔍 Checking port 8000..."
if lsof -i :8000 >/dev/null 2>&1; then
    echo "✅ Something is listening on port 8000"
    lsof -i :8000
else
    echo "❌ Nothing listening on port 8000"
fi

# Kill any existing processes and start fresh
echo ""
echo "🔄 Starting fresh Django server..."
pkill -f "python manage.py runserver" 2>/dev/null
pkill -f "127.0.0.1:8000" 2>/dev/null
sleep 2

# Start Django with verbose output
echo "🚀 Starting Django server with debugging..."
python manage.py runserver 127.0.0.1:8000 --verbosity=2 &
DJANGO_PID=$!

echo "Django PID: $DJANGO_PID"
sleep 5

# Test the specific endpoints that are failing
echo ""
echo "🧪 Testing API endpoints..."

# Test health endpoint first
echo "1. Testing health endpoint..."
HEALTH_STATUS=$(curl -s -w "HTTPSTATUS:%{http_code}" http://127.0.0.1:8000/api/auth/health/ 2>/dev/null)
if echo "$HEALTH_STATUS" | grep -q "HTTPSTATUS:200"; then
    echo "✅ Health endpoint working"
else
    echo "❌ Health endpoint failed: $HEALTH_STATUS"
fi

# Test Google OAuth URL endpoint (the one failing in JavaScript)
echo ""
echo "2. Testing Google OAuth URL endpoint..."
OAUTH_STATUS=$(curl -s -w "HTTPSTATUS:%{http_code}" http://127.0.0.1:8000/api/auth/oauth/google/url/ 2>/dev/null)
if echo "$OAUTH_STATUS" | grep -q "HTTPSTATUS:200"; then
    echo "✅ OAuth URL endpoint working"
    echo "$OAUTH_STATUS" | sed 's/HTTPSTATUS:[0-9]*//' | python3 -m json.tool 2>/dev/null || echo "Response format issue"
else
    echo "❌ OAuth URL endpoint failed: $OAUTH_STATUS"
fi

# Test Google config endpoint
echo ""
echo "3. Testing Google config endpoint..."
CONFIG_STATUS=$(curl -s -w "HTTPSTATUS:%{http_code}" http://127.0.0.1:8000/api/auth/config/google/ 2>/dev/null)
if echo "$CONFIG_STATUS" | grep -q "HTTPSTATUS:200"; then
    echo "✅ Config endpoint working"
    echo "$CONFIG_STATUS" | sed 's/HTTPSTATUS:[0-9]*//' | python3 -m json.tool 2>/dev/null
else
    echo "❌ Config endpoint failed: $CONFIG_STATUS"
fi

# Test basic login page
echo ""
echo "4. Testing login page..."
LOGIN_STATUS=$(curl -s -w "HTTPSTATUS:%{http_code}" http://127.0.0.1:8000/login/ 2>/dev/null)
if echo "$LOGIN_STATUS" | grep -q "HTTPSTATUS:200"; then
    echo "✅ Login page accessible"
else
    echo "❌ Login page failed: $LOGIN_STATUS"
fi

echo ""
echo "🔧 Debugging Information:"
echo "Django server PID: $DJANGO_PID"
echo "Check Django terminal for error messages"
echo ""
echo "If endpoints are failing, possible causes:"
echo "1. CORS issues (cross-origin requests blocked)"
echo "2. Django settings configuration"
echo "3. URL routing problems"
echo "4. Environment variables not loaded"
echo ""

echo "🧪 Manual testing:"
echo "Try these URLs in your browser:"
echo "- http://127.0.0.1:8000/login/ (should show login page)"
echo "- http://127.0.0.1:8000/api/auth/health/ (should show JSON)"
echo "- http://127.0.0.1:8000/api/auth/oauth/google/url/ (should show OAuth URL)"
echo ""

echo "Server is running. Check the Django terminal for detailed error messages."
