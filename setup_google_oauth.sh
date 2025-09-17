#!/bin/bash

echo "=== Google OAuth Setup Guide ==="
echo ""
echo "🔧 Step 1: Create Google Cloud Project (if needed)"
echo "   1. Visit: https://console.cloud.google.com"
echo "   2. Create a new project or select existing one"
echo ""
echo "🔧 Step 2: Enable Google+ API"
echo "   1. Go to APIs & Services > Library"
echo "   2. Search for 'Google+ API' and enable it"
echo "   3. Also enable 'Google OAuth2 API'"
echo ""
echo "🔧 Step 3: Create OAuth 2.0 Credentials"
echo "   1. Go to APIs & Services > Credentials"
echo "   2. Click 'Create Credentials' > 'OAuth 2.0 Client IDs'"
echo "   3. Choose 'Web application'"
echo "   4. Name: 'Barge2Rail SSO'"
echo ""
echo "🔧 Step 4: Configure Authorized Redirect URIs"
echo "   Add these exact URIs:"
echo "   - http://127.0.0.1:8000/auth/google/callback/"
echo "   - http://localhost:8000/auth/google/callback/"
echo ""
echo "🔧 Step 5: Get Your Credentials"
echo "   After creating, copy:"
echo "   - Client ID (looks like: 123456789-abcdef.apps.googleusercontent.com)"
echo "   - Client Secret (looks like: <GOOGLE_CLIENT_SECRET>)"
echo ""
echo "🔧 Step 6: Update Environment Variables"
echo "   Run this script with your new credentials:"
echo "   ./setup_google_oauth.sh update YOUR_CLIENT_ID YOUR_CLIENT_SECRET"
echo ""

if [ "$1" = "update" ]; then
    if [ -z "$2" ] || [ -z "$3" ]; then
        echo "❌ Error: Please provide both CLIENT_ID and CLIENT_SECRET"
        echo "Usage: ./setup_google_oauth.sh update YOUR_CLIENT_ID YOUR_CLIENT_SECRET"
        exit 1
    fi
    
    CLIENT_ID="$2"
    CLIENT_SECRET="$3"
    
    echo "🔄 Updating .env file..."
    
    # Backup original .env
    cp .env .env.backup.$(date +%Y%m%d_%H%M%S)
    
    # Update the .env file
    sed -i '' "s/GOOGLE_CLIENT_ID=.*/GOOGLE_CLIENT_ID=$CLIENT_ID/" .env
    sed -i '' "s/GOOGLE_CLIENT_SECRET=.*/GOOGLE_CLIENT_SECRET=$CLIENT_SECRET/" .env
    
    echo "✅ Updated .env file with new Google OAuth credentials"
    echo "🔄 Restarting Django server..."
    
    # Find and kill existing Django server
    pkill -f "python manage.py runserver"
    sleep 2
    
    # Start Django server in background
    python manage.py runserver &
    echo "✅ Django server restarted"
    echo ""
    echo "🧪 Test your setup:"
    echo "   Visit: http://127.0.0.1:8000/api/auth/config/google/"
    echo "   Then try: http://127.0.0.1:8000/login/"
    
elif [ "$1" = "test" ]; then
    echo "🧪 Testing current Google OAuth configuration..."
    
    # Test configuration endpoint
    echo "📋 Current configuration:"
    curl -s http://127.0.0.1:8000/api/auth/config/google/ | python -m json.tool 2>/dev/null || echo "❌ Django server not running or endpoint not accessible"
    
    echo ""
    echo "🔗 OAuth URL test:"
    curl -s http://127.0.0.1:8000/api/auth/oauth/google/url/ | python -m json.tool 2>/dev/null || echo "❌ OAuth URL endpoint not accessible"
    
elif [ "$1" = "restart" ]; then
    echo "🔄 Restarting Django server..."
    pkill -f "python manage.py runserver"
    sleep 2
    python manage.py runserver &
    echo "✅ Django server restarted"
    
else
    echo "Available commands:"
    echo "  ./setup_google_oauth.sh update CLIENT_ID CLIENT_SECRET  # Update credentials"
    echo "  ./setup_google_oauth.sh test                            # Test current setup"
    echo "  ./setup_google_oauth.sh restart                         # Restart Django server"
fi
