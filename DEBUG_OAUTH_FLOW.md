# OAuth Flow Debugging Checklist

## Current Issues
1. State parameter mismatch when using test URLs
2. Old dashboard showing deleted applications
3. OAuth flow not completing properly

## Systems Involved
1. **PrimeTrade** (http://127.0.0.1:8001) - The client application
2. **SSO** (https://sso.barge2rail.com) - The OAuth server
3. **Google OAuth** - Identity provider for SSO

## OAuth Flow Steps (What Should Happen)

### Step 1: Initiate OAuth
- User visits: http://127.0.0.1:8001/login/
- Clicks "Login with SSO"
- PrimeTrade generates random state, stores in session
- Redirects to: https://sso.barge2rail.com/auth/authorize/?...

### Step 2: SSO Authorization
- SSO receives OAuth request with:
  - client_id: app_0b97b7b94d192797
  - redirect_uri: http://127.0.0.1:8001/auth/callback/
  - response_type: code
  - state: [random string from PrimeTrade]
- If not logged in: Redirect to SSO login
- If logged in: Generate auth code, redirect back

### Step 3: SSO Login (if needed)
- User logs in via Google OAuth
- SSO creates session
- Redirects back to /auth/authorize/ with original params

### Step 4: Authorization Code Generation
- SSO validates user has access to PrimeTrade app
- Generates authorization code
- Redirects to: http://127.0.0.1:8001/auth/callback/?code=XXX&state=YYY

### Step 5: Token Exchange
- PrimeTrade receives callback
- Validates state matches stored state
- Exchanges code for tokens at: https://sso.barge2rail.com/auth/token/
- Creates user session with JWT data
- Redirects to PrimeTrade dashboard

## Debug Commands

### 1. Check SSO Database for Old Data
```bash
cd /Users/cerion/Projects/barge2rail-auth
python manage.py shell

from sso.models import Application
apps = Application.objects.all()
for app in apps:
    print(f"{app.name}: {app.client_id} - Created: {app.created_at} - Active: {app.is_active}")
```

### 2. Check PrimeTrade Session State
```python
# In PrimeTrade Django shell
from django.contrib.sessions.models import Session
sessions = Session.objects.all()
for s in sessions:
    data = s.get_decoded()
    if 'oauth_state' in data:
        print(f"Session has oauth_state: {data['oauth_state']}")
```

### 3. Test OAuth URL Generation in PrimeTrade
```bash
cd /Users/cerion/Projects/django-primetrade
python manage.py shell

from django.conf import settings
from urllib.parse import urlencode
import secrets

state = secrets.token_urlsafe(32)
params = {
    'client_id': settings.SSO_CLIENT_ID,
    'redirect_uri': settings.SSO_REDIRECT_URI,
    'response_type': 'code',
    'scope': settings.SSO_SCOPES,
    'state': state,
}
auth_url = f"{settings.SSO_BASE_URL}/auth/authorize/?{urlencode(params)}"
print(f"Generated URL: {auth_url}")
print(f"State: {state}")
```

## Fix Priority

### 1. IMMEDIATE: Fix State Validation
- Problem: Manual test URL uses "test123" which doesn't match session
- Solution: Always use PrimeTrade's "Login with SSO" button

### 2. HIGH: Clean SSO Database
- Problem: Showing old deleted applications
- Solution: Remove old Application records from database

### 3. MEDIUM: Fix SSO Login Redirect
- Problem: After SSO login, not returning to OAuth flow
- Solution: Check if /login/ is preserving ?next= parameter

### 4. LOW: Improve Error Messages
- Problem: "Invalid state" doesn't explain the issue
- Solution: Better error pages with debugging info

## Testing Sequence

### Test 1: Clean OAuth Flow
1. Clear all cookies/sessions
2. Visit http://127.0.0.1:8001/login/
3. Click "Login with SSO"
4. Complete Google login
5. Should return to PrimeTrade logged in

### Test 2: Already Logged Into SSO
1. Login to SSO directly first
2. Then visit http://127.0.0.1:8001/login/
3. Click "Login with SSO"
4. Should immediately redirect back with code

### Test 3: Token Exchange
1. Monitor PrimeTrade console for token exchange
2. Should see POST to /auth/token/
3. Should receive JWT tokens
4. Should create user session

## Common Failures and Fixes

### "Invalid state parameter"
- Cause: State mismatch between sent and received
- Fix: Don't use manual test URLs, use actual OAuth flow

### "Invalid redirect_uri"
- Cause: Redirect URI doesn't match registered URIs
- Fix: Check exact match including trailing slashes

### "You don't have access to PrimeTrade"
- Cause: User doesn't have UserRole for PrimeTrade app
- Fix: Add UserRole in SSO admin

### OAuth completes but not logged into PrimeTrade
- Cause: Token exchange failed or user creation failed
- Fix: Check PrimeTrade logs for errors

## Next Steps

1. Clean up SSO database (remove old applications)
2. Test clean OAuth flow with proper state
3. Fix any remaining redirect issues
4. Document working flow
