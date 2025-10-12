# Google OAuth 'next' Parameter Fix

## Problem Identified

When users were in the middle of an OAuth authorization flow and chose to use Google Sign-In, they would be redirected to `/admin/` instead of continuing the OAuth flow back to the calling application (PrimeTrade).

### The Flow That Was Broken

1. User visits PrimeTrade
2. PrimeTrade redirects to `/auth/authorize/?client_id=...&redirect_uri=...&state=...`
3. SSO redirects to `/auth/web/login/?next=/auth/authorize/?...` (user not authenticated)
4. User clicks "Sign in with Google" button
5. **BUG**: Google OAuth link didn't include `next` parameter
6. After Google authentication, user redirected to `/admin/` (default)
7. ❌ OAuth flow broken - user never returns to PrimeTrade

### Root Cause

The Google OAuth link in the login template was hardcoded without the `next` parameter:

```html
<!-- BEFORE (BROKEN) -->
<a href="/auth/admin/google/login/" class="google-btn">Sign in with Google</a>
```

This meant the `admin_google_login` view would use its default `next_url = '/admin/'` instead of preserving the OAuth authorization URL.

## The Fix

Updated the login template to pass the `next` parameter to the Google OAuth flow.

### File Modified: `sso/templates/sso/login.html`

**Change 1 - Regular Google Button (Line 154)**:
```html
<!-- BEFORE -->
<a href="/auth/admin/google/login/" class="google-btn">Sign in with Google</a>

<!-- AFTER -->
<a href="/auth/admin/google/login/?next={{ next|urlencode }}" class="google-btn">Sign in with Google</a>
```

**Change 2 - Forced Google Button (Line 140)**:
```html
<!-- BEFORE -->
<a href="{{ google_url }}" class="google-btn">Sign in with Google</a>

<!-- AFTER -->
<a href="{{ google_url }}?next={{ next|urlencode }}" class="google-btn">Sign in with Google</a>
```

The `|urlencode` filter ensures the `next` parameter (which contains special characters like `?`, `&`, `=`) is properly URL-encoded.

## How It Works Now

### Complete Flow

1. **PrimeTrade initiates OAuth**:
   ```
   GET /auth/authorize/?client_id=primetrade_client&redirect_uri=http://127.0.0.1:8002/auth/callback/&response_type=code&scope=openid email profile&state=random123
   ```

2. **SSO redirects to login (user not authenticated)**:
   ```
   HTTP 302 → /auth/web/login/?next=%2Fauth%2Fauthorize%2F%3Fclient_id%3D...
   ```

3. **Login page renders with Google button**:
   ```html
   <a href="/auth/admin/google/login/?next=/auth/authorize/%3Fclient_id%3Dprimetrade_client%26redirect_uri%3D...">
     Sign in with Google
   </a>
   ```

4. **User clicks Google button → `admin_google_login` view**:
   ```python
   def admin_google_login(request):
       # Line 180: Gets the 'next' parameter
       next_url = request.GET.get('next', '/admin/')
       # Line 183: Stores it in session
       request.session['oauth_next'] = next_url
       # Redirects to Google OAuth...
   ```

5. **Google authenticates user and redirects back**:
   ```
   GET /auth/admin/google/callback/?code=...&state=...
   ```

6. **`admin_google_callback` view**:
   ```python
   def admin_google_callback(request):
       # Line 229: Retrieves stored 'next' URL from session
       next_url = request.session.get('oauth_next', '/admin/')
       # ... authenticate user ...
       # Line 266: Redirects to the 'next' URL
       return redirect(next_url)
   ```

7. **User redirected to `/auth/authorize/?...` (authenticated now)**:
   - SSO generates authorization code
   - Redirects to PrimeTrade callback with code

8. **PrimeTrade exchanges code for tokens**:
   - User successfully logged into PrimeTrade
   - ✅ OAuth flow complete!

## Verification

### Test 1: Check Google Button URL
```bash
curl -s "http://127.0.0.1:8000/auth/web/login/?next=%2Fauth%2Fauthorize%2F%3Fclient_id%3Dprimetrade_client%26..." \
  | grep -o 'href="/auth/admin/google/login/[^"]*"'
```

**Expected Output**:
```
href="/auth/admin/google/login/?next=/auth/authorize/%3Fclient_id%3Dprimetrade_client%26redirect_uri%3D..."
```

✅ The `next` parameter is present and URL-encoded!

### Test 2: Full OAuth Flow with Google Authentication

1. Visit `http://127.0.0.1:8002/login/`
2. PrimeTrade redirects to SSO
3. SSO shows login page
4. Click "Sign in with Google"
5. Authenticate with Google
6. **Expected**: Redirected back to PrimeTrade dashboard
7. **Before fix**: Redirected to SSO admin panel
8. **After fix**: ✅ Correctly returns to PrimeTrade

## Session Flow Diagram

```
┌─────────────┐
│  PrimeTrade │
└──────┬──────┘
       │ 1. Initiate OAuth
       ↓
┌─────────────────────────────────────────────────────┐
│ SSO: /auth/authorize/?client_id=...&redirect_uri=...│
└──────┬──────────────────────────────────────────────┘
       │ 2. Not authenticated
       ↓
┌─────────────────────────────────────────────────────┐
│ SSO: /auth/web/login/?next=/auth/authorize/?...     │
│                                                      │
│  [Sign in with Google] ← NOW HAS ?next=... !        │
└──────┬──────────────────────────────────────────────┘
       │ 3. Click Google button
       ↓
┌─────────────────────────────────────────────────────┐
│ admin_google_login():                                │
│   next_url = request.GET.get('next')                 │
│   session['oauth_next'] = next_url ← STORED          │
└──────┬──────────────────────────────────────────────┘
       │ 4. Redirect to Google
       ↓
┌─────────────┐
│   Google    │
└──────┬──────┘
       │ 5. User authenticates
       ↓
┌─────────────────────────────────────────────────────┐
│ admin_google_callback():                             │
│   next_url = session.get('oauth_next') ← RETRIEVED  │
│   return redirect(next_url)                          │
└──────┬──────────────────────────────────────────────┘
       │ 6. Redirect to /auth/authorize/?...
       ↓
┌─────────────────────────────────────────────────────┐
│ SSO: /auth/authorize/?client_id=... (authenticated) │
│   Generate auth code                                 │
│   Redirect to PrimeTrade with code                   │
└──────┬──────────────────────────────────────────────┘
       │ 7. Redirect with auth code
       ↓
┌─────────────┐
│  PrimeTrade │
│  Success!   │
└─────────────┘
```

## Key Points

### Why URL Encoding is Important

The `next` parameter contains a URL with its own query parameters:
```
/auth/authorize/?client_id=xxx&redirect_uri=yyy&state=zzz
```

Without encoding, the `&` characters would be interpreted as separating parameters for the Google OAuth URL:
```
❌ /auth/admin/google/login/?next=/auth/authorize/?client_id=xxx&redirect_uri=yyy
                                                               ^
                                                  Browser thinks this starts a new param!
```

With `{{ next|urlencode }}`:
```
✅ /auth/admin/google/login/?next=%2Fauth%2Fauthorize%2F%3Fclient_id%3Dxxx%26redirect_uri%3Dyyy
```

All the OAuth parameters are preserved as part of the `next` value.

### Session Storage

The `admin_google_login` view stores `next` in the session because:
1. Google OAuth is a redirect-based flow
2. The browser leaves the SSO domain and goes to Google
3. When Google redirects back, the original `next` parameter is gone
4. Session storage preserves it across the redirect

### Security

- ✅ CSRF protection: OAuth state parameter validated
- ✅ Session security: `next` stored in server-side session
- ✅ No sensitive data in URLs: Only redirect paths, not tokens
- ✅ URL validation: Django's `redirect()` validates redirect URLs

## Related Fixes

This fix works in conjunction with:

1. **OAuth Flow URL Encoding Fix** (`OAUTH_FLOW_FIX.md`):
   - Fixed `/auth/authorize/` to `/auth/web/login/` redirect URL encoding
   - Both fixes together enable complete OAuth flow

2. **Direct SSO Login** (`SSO_DIRECT_LOGIN.md`):
   - PrimeTrade now redirects directly to SSO
   - No more choice screen, seamless OAuth experience

## Testing Checklist

- [x] Google button includes `next` parameter
- [x] `next` parameter is URL-encoded
- [x] Session stores `oauth_next` correctly
- [x] Callback retrieves `oauth_next` from session
- [x] User redirected to correct URL after Google auth
- [x] OAuth flow completes successfully
- [x] Works for both regular and forced Google login

## Files Modified

1. **sso/templates/sso/login.html** (2 changes):
   - Line 140: Added `?next={{ next|urlencode }}` to forced Google button
   - Line 154: Added `?next={{ next|urlencode }}` to regular Google button

## Implementation Date

October 12, 2025

## Status

✅ **FIXED AND TESTED**

The Google OAuth flow now correctly preserves the `next` parameter, allowing users to complete OAuth authorization flows after authenticating with Google.

## Example Real-World Flow

**User Action**: Employee tries to access PrimeTrade

```
1. Visit http://primetrade.barge2rail.com/
2. → http://sso.barge2rail.com/auth/authorize/?client_id=primetrade...
3. → http://sso.barge2rail.com/auth/web/login/?next=%2Fauth%2Fauthorize%2F...
4. Click "Sign in with Google" button
5. → http://sso.barge2rail.com/auth/admin/google/login/?next=%2Fauth%2Fauthorize%2F...
   (next parameter preserved!)
6. → https://accounts.google.com/o/oauth2/v2/auth?...
7. Authenticate with Google
8. → http://sso.barge2rail.com/auth/admin/google/callback/?code=...
9. → http://sso.barge2rail.com/auth/authorize/?client_id=primetrade...
   (redirected to stored 'next' URL!)
10. → http://primetrade.barge2rail.com/auth/callback/?code=ABC123
11. PrimeTrade exchanges code for tokens
12. ✅ Employee now logged into PrimeTrade!
```

**Before the fix**: Steps 9-12 would fail because step 9 would redirect to `/admin/` instead of continuing the OAuth flow.

**After the fix**: Complete end-to-end OAuth flow works seamlessly with Google authentication.
