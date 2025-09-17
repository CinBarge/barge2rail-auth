#!/bin/bash

echo "=== Complete Django Server Fix ==="
echo ""

cd /Users/cerion/Projects/barge2rail-auth

# Ensure we're in the right directory
echo "Working directory: $(pwd)"
echo ""

# Check if manage.py exists
if [ ! -f "manage.py" ]; then
    echo "ERROR: manage.py not found. Are you in the right directory?"
    exit 1
fi

# Stop all Django processes completely
echo "Stopping all Django processes..."
pkill -f "python.*manage.py" 2>/dev/null
pkill -f "runserver" 2>/dev/null
sleep 3

# Check if port 8000 is still occupied
if lsof -i :8000 >/dev/null 2>&1; then
    echo "Force killing processes on port 8000..."
    lsof -ti :8000 | xargs kill -9 2>/dev/null
    sleep 2
fi

# Check Django configuration
echo "Checking Django configuration..."
python manage.py check --deploy 2>&1 | head -5

# Start Django server with explicit settings
echo ""
echo "Starting Django server..."
export DJANGO_SETTINGS_MODULE=core.settings
python manage.py runserver 127.0.0.1:8000 --insecure &
DJANGO_PID=$!

echo "Django server started with PID: $DJANGO_PID"

# Wait longer for server to fully start
echo "Waiting for server to initialize..."
sleep 8

# Test server is actually running
echo ""
echo "Testing if server is accessible..."

# Try multiple times as server might still be starting
for attempt in {1..15}; do
    if curl -s http://127.0.0.1:8000/login/ >/dev/null 2>&1; then
        echo "SUCCESS: Server is responding on attempt $attempt"
        break
    else
        echo "Attempt $attempt: Server not ready, waiting..."
        sleep 2
    fi
    
    if [ $attempt -eq 15 ]; then
        echo "ERROR: Server failed to start after 15 attempts"
        echo "Check the Django terminal for error messages"
        exit 1
    fi
done

# Test API endpoints
echo ""
echo "Testing API endpoints..."

# Test each endpoint individually
endpoints=("health" "config/google" "oauth/google/url")

for endpoint in "${endpoints[@]}"; do
    echo "Testing /api/auth/$endpoint/..."
    response=$(curl -s -w "HTTP:%{http_code}" "http://127.0.0.1:8000/api/auth/$endpoint/" 2>/dev/null)
    http_code=$(echo "$response" | sed -n 's/.*HTTP:\([0-9]*\).*/\1/p')
    
    if [ "$http_code" = "200" ]; then
        echo "  ✅ $endpoint: Working (200)"
    else
        echo "  ❌ $endpoint: Failed ($http_code)"
    fi
done

echo ""
echo "Testing login page..."
login_status=$(curl -s -w "HTTP:%{http_code}" http://127.0.0.1:8000/login/ 2>/dev/null | sed -n 's/.*HTTP:\([0-9]*\).*/\1/p')

if [ "$login_status" = "200" ]; then
    echo "✅ Login page: Working (200)"
else
    echo "❌ Login page: Failed ($login_status)"
fi

# Create a simple test HTML page to verify JavaScript can reach the server
cat > /tmp/test_django.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Test Django Connection</title>
</head>
<body>
    <h1>Django API Test</h1>
    <button onclick="testAPI()">Test API Connection</button>
    <div id="results"></div>
    
    <script>
    async function testAPI() {
        const results = document.getElementById('results');
        results.innerHTML = 'Testing...<br>';
        
        const endpoints = [
            'http://127.0.0.1:8000/api/auth/health/',
            'http://127.0.0.1:8000/api/auth/config/google/',
            'http://127.0.0.1:8000/api/auth/oauth/google/url/'
        ];
        
        for (const url of endpoints) {
            try {
                const response = await fetch(url);
                results.innerHTML += url + ': ' + response.status + ' ' + response.statusText + '<br>';
            } catch (error) {
                results.innerHTML += url + ': ERROR - ' + error.message + '<br>';
            }
        }
    }
    </script>
</body>
</html>
EOF

echo ""
echo "Created test page at /tmp/test_django.html"
echo ""
echo "Summary:"
echo "✅ Django server is running (PID: $DJANGO_PID)"
echo "✅ Server accessible on http://127.0.0.1:8000"
echo ""
echo "Next steps:"
echo "1. Open http://127.0.0.1:8000/login/ in browser"
echo "2. Try the Google OAuth flow again"
echo "3. If still having issues, open /tmp/test_django.html to test API connectivity"
echo ""
echo "To stop server: kill $DJANGO_PID"
echo "Django terminal shows server logs and any errors"
