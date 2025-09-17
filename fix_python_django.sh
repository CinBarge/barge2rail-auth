#!/bin/bash

echo "=== Django Server Fix - Python Detection ==="
echo ""

cd /Users/cerion/Projects/barge2rail-auth

# Detect correct Python command
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
    echo "Using python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
    echo "Using python"
else
    echo "ERROR: Neither python nor python3 found in PATH"
    echo "Please install Python or add it to your PATH"
    exit 1
fi

# Verify Python version
echo "Python version: $($PYTHON_CMD --version)"
echo ""

# Stop existing processes
echo "Stopping Django processes..."
pkill -f "python.*manage.py" 2>/dev/null
pkill -f "python3.*manage.py" 2>/dev/null
pkill -f "runserver" 2>/dev/null
sleep 2

# Kill port 8000 processes
if lsof -i :8000 >/dev/null 2>&1; then
    echo "Killing processes on port 8000..."
    lsof -ti :8000 | xargs kill -9 2>/dev/null
    sleep 2
fi

# Check Django setup
echo "Checking Django..."
if [ ! -f "manage.py" ]; then
    echo "ERROR: manage.py not found"
    exit 1
fi

$PYTHON_CMD manage.py check --deploy 2>&1 | head -5

# Start Django server
echo ""
echo "Starting Django server with $PYTHON_CMD..."
$PYTHON_CMD manage.py runserver 127.0.0.1:8000 --insecure &
DJANGO_PID=$!

echo "Django PID: $DJANGO_PID"
sleep 6

# Test server
echo ""
echo "Testing server..."
for i in {1..10}; do
    if curl -s http://127.0.0.1:8000/login/ >/dev/null 2>&1; then
        echo "SUCCESS: Server responding on attempt $i"
        break
    else
        echo "Attempt $i: Waiting for server..."
        sleep 3
    fi
    
    if [ $i -eq 10 ]; then
        echo "Server failed to start. Checking process..."
        if ps -p $DJANGO_PID > /dev/null; then
            echo "Django process still running, might be slow to start"
        else
            echo "Django process died. Check for errors:"
            echo "Try manually: $PYTHON_CMD manage.py runserver"
        fi
        exit 1
    fi
done

# Test API endpoints
echo ""
echo "Testing API endpoints..."
for endpoint in "health" "config/google" "oauth/google/url"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8000/api/auth/$endpoint/")
    if [ "$status" = "200" ]; then
        echo "API $endpoint: OK ($status)"
    else
        echo "API $endpoint: FAIL ($status)"
    fi
done

# Test OAuth URL specifically (the one causing JavaScript errors)
echo ""
echo "Testing Google OAuth URL generation:"
oauth_response=$(curl -s "http://127.0.0.1:8000/api/auth/oauth/google/url/")
if echo "$oauth_response" | grep -q "auth_url"; then
    echo "SUCCESS: Google OAuth URL endpoint working"
else
    echo "FAILED: OAuth URL endpoint returned: $oauth_response"
fi

echo ""
echo "Server Status:"
echo "PID: $DJANGO_PID"
echo "URL: http://127.0.0.1:8000"
echo "Login: http://127.0.0.1:8000/login/"
echo ""
echo "Try the Google OAuth flow again:"
echo "1. Go to http://127.0.0.1:8000/login/"
echo "2. Click Google tab"
echo "3. Click Continue with Google"
echo ""
echo "To stop: kill $DJANGO_PID"
