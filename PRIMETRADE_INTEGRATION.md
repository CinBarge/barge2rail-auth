# PrimeTrade SSO Integration Checklist
**Created:** December 10, 2024
**Status:** SSO Ready, PrimeTrade Integration Pending

## ✅ SSO Prerequisites (COMPLETE)

### OAuth Endpoints Validated
- ✅ Authorization: `https://sso.barge2rail.com/auth/authorize/`
- ✅ Token Exchange: `https://sso.barge2rail.com/auth/token/`
- ✅ User Info: `https://sso.barge2rail.com/auth/me/`
- ✅ Logout: `https://sso.barge2rail.com/auth/logout/`
- ✅ Health Check: `https://sso.barge2rail.com/auth/health/`

### PrimeTrade Application Configuration
- ✅ Client ID: `app_0b97b7b94d192797`
- ✅ Client Secret: `Kyq6_cHugJLcWyYuP1K1JSf-eF59y0OHT6IJ7tMet4U`
- ✅ Local Redirect: `http://127.0.0.1:8001/auth/callback/`
- ✅ Production Redirect: `https://prt.barge2rail.com/auth/callback/`

### Validated OAuth Flow
1. ✅ User clicks login in PrimeTrade
2. ✅ Redirect to SSO authorize endpoint
3. ✅ User logs in with Google
4. ✅ SSO redirects back with authorization code
5. ✅ PrimeTrade exchanges code for tokens
6. ✅ PrimeTrade uses access token for API calls

---

## 📋 PrimeTrade Integration Steps

### Step 1: Update PrimeTrade Environment Variables
```bash
# Add to PrimeTrade .env file
SSO_CLIENT_ID=app_0b97b7b94d192797
SSO_CLIENT_SECRET=Kyq6_cHugJLcWyYuP1K1JSf-eF59y0OHT6IJ7tMet4U
SSO_AUTHORIZE_URL=https://sso.barge2rail.com/auth/authorize/
SSO_TOKEN_URL=https://sso.barge2rail.com/auth/token/
SSO_USER_INFO_URL=https://sso.barge2rail.com/auth/me/
SSO_LOGOUT_URL=https://sso.barge2rail.com/auth/logout/
SSO_REDIRECT_URI=http://127.0.0.1:8001/auth/callback/  # For local dev
# SSO_REDIRECT_URI=https://prt.barge2rail.com/auth/callback/  # For production
```

### Step 2: Implement OAuth Flow in PrimeTrade

#### Login Button
```python
# Generate login URL
def get_sso_login_url():
    params = {
        'response_type': 'code',
        'client_id': settings.SSO_CLIENT_ID,
        'redirect_uri': settings.SSO_REDIRECT_URI,
        'scope': 'openid email profile',
        'state': generate_random_state()  # CSRF protection
    }
    return f"{settings.SSO_AUTHORIZE_URL}?{urlencode(params)}"
```

#### Callback Handler
```python
def sso_callback(request):
    # Get authorization code
    code = request.GET.get('code')
    state = request.GET.get('state')
    
    # Verify state for CSRF protection
    if not verify_state(state):
        return HttpResponse("Invalid state", status=400)
    
    # Exchange code for tokens
    token_response = requests.post(
        settings.SSO_TOKEN_URL,
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': settings.SSO_REDIRECT_URI,
            'client_id': settings.SSO_CLIENT_ID,
            'client_secret': settings.SSO_CLIENT_SECRET
        }
    )
    
    tokens = token_response.json()
    access_token = tokens['access_token']
    refresh_token = tokens['refresh_token']
    user_data = tokens['user']
    
    # Create/update local user session
    # Store tokens securely
    # Redirect to PrimeTrade dashboard
```

#### API Authentication
```python
def make_authenticated_request(access_token, endpoint):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    return requests.get(endpoint, headers=headers)
```

### Step 3: Update PrimeTrade UI
- [ ] Replace existing login form with SSO login button
- [ ] Add "Login with Barge2Rail SSO" button
- [ ] Handle loading states during OAuth flow
- [ ] Add logout functionality

### Step 4: Test OAuth Flow
- [ ] Test local development flow (127.0.0.1:8001)
- [ ] Test production flow (prt.barge2rail.com)
- [ ] Test token refresh
- [ ] Test logout

### Step 5: Handle Edge Cases
- [ ] Token expiration and refresh
- [ ] SSO unavailable fallback
- [ ] User cancels OAuth flow
- [ ] Invalid/expired authorization codes

---

## 🔧 Testing Commands

### Test Authorization URL Generation
```bash
# This is what PrimeTrade should generate
echo "https://sso.barge2rail.com/auth/authorize/?response_type=code&client_id=app_0b97b7b94d192797&redirect_uri=http://127.0.0.1:8001/auth/callback/&scope=openid email profile&state=random_state_here"
```

### Manual Token Exchange Test
```bash
# After getting authorization code from OAuth flow
curl -X POST https://sso.barge2rail.com/auth/token/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=[AUTHORIZATION_CODE]" \
  -d "redirect_uri=http://127.0.0.1:8001/auth/callback/" \
  -d "client_id=app_0b97b7b94d192797" \
  -d "client_secret=Kyq6_cHugJLcWyYuP1K1JSf-eF59y0OHT6IJ7tMet4U"
```

### Test Authenticated Request
```bash
# Use access token from above
curl -X GET https://sso.barge2rail.com/auth/me/ \
  -H "Authorization: Bearer [ACCESS_TOKEN]"
```

---

## 📊 Success Metrics

- [ ] Users can log into PrimeTrade via SSO
- [ ] No more separate PrimeTrade passwords
- [ ] User roles from SSO apply in PrimeTrade
- [ ] Session management works correctly
- [ ] Logout from PrimeTrade clears SSO session

---

## 🚀 Next Steps After Integration

1. **Remove PrimeTrade's local authentication**
   - Disable local user registration
   - Migrate existing users to SSO
   - Remove password management code

2. **Implement role-based access**
   - Use SSO roles for PrimeTrade permissions
   - Map SSO admin role to PrimeTrade admin

3. **Add other applications**
   - Repair ticketing system
   - Barge tracking system
   - Employee management system

---

## 📝 Notes

- SSO uses JWT tokens - all user info is in the token
- Tokens expire in ~15 minutes (access) and ~7 days (refresh)
- Always validate state parameter for CSRF protection
- Store refresh tokens securely (encrypted database or secure cookie)

---

## Status: Ready for PrimeTrade Integration

The SSO is fully operational and tested. PrimeTrade can now be integrated following the steps above.
