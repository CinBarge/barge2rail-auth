#!/bin/bash

echo "🔧 Starting Google Authentication Diagnostic"
echo "============================================="

# Activate virtual environment
source venv/bin/activate

# Start Django server
echo "🚀 Starting Django development server..."
python manage.py runserver 127.0.0.1:8000 &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Check if server is running
if curl -s http://127.0.0.1:8000/ >/dev/null; then
    echo "✅ Django server is running"
    echo ""
    echo "🌐 Open the following URLs in your browser:"
    echo ""
    echo "📊 Comprehensive Diagnostic Tool:"
    echo "   http://127.0.0.1:8000/login/google-diagnostic/"
    echo ""
    echo "🧪 Additional Test Pages:"
    echo "   http://127.0.0.1:8000/login/google-test/"
    echo "   http://127.0.0.1:8000/login/google-onetap/"
    echo ""
    echo "Press Ctrl+C to stop the server"
    
    # Keep script running
    wait $SERVER_PID
else
    echo "❌ Failed to start Django server"
    kill $SERVER_PID 2>/dev/null
fi
