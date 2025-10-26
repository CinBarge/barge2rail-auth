# Google OAuth Manual Testing with cURL

Quick reference for testing Google OAuth endpoints manually.

## Prerequisites

1. **Start the server:**
   ```bash
   python manage.py runserver
   ```

2. **Get tokens via browser:**
   - Navigate to: http://localhost:8000/api/auth/login/google/
   - Sign in with Google
   - Copy `access_token` and `refresh_token` from redirect URL

---

## Test 1: Token Verification

**Endpoint:** `POST /api/auth/validate/`

**Description:** Validates a JWT access token and returns user information.

```bash
curl -X POST http://localhost:8000/api/auth/validate/ \
  -H "Content-Type: application/json" \
  -d '{"token": "YOUR_ACCESS_TOKEN_HERE"}'
```

**Expected Response (200 OK):**
```json
{
  "valid": true,
  "user": {
    "id": "...",
    "email": "user@example.com",
    "display_name": "User Name",
    "auth_type": "google",
    "is_sso_admin": false
  },
  "claims": {
    "user_id": "...",
    "email": "user@example.com",
    "exp": 1234567890,
    "iat": 1234566990
  }
}
```

---

## Test 2: Token Refresh

**Endpoint:** `POST /api/auth/refresh/`

**Description:** Exchanges a refresh token for a new access token.

```bash
curl -X POST http://localhost:8000/api/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "YOUR_REFRESH_TOKEN_HERE"}'
```

**Expected Response (200 OK):**
```json
{
  "access": "NEW_ACCESS_TOKEN",
  "refresh": "NEW_REFRESH_TOKEN"
}
```

**Note:** With `ROTATE_REFRESH_TOKENS=True`, you'll get a new refresh token. The old refresh token is blacklisted.

---

## Test 3: User Profile (Authenticated)

**Endpoint:** `GET /api/auth/me/`

**Description:** Retrieves authenticated user profile using Bearer token.

```bash
curl -X GET http://localhost:8000/api/auth/me/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"
```

**Expected Response (200 OK):**
```json
{
  "id": "...",
  "email": "user@example.com",
  "display_name": "User Name",
  "auth_type": "google",
  "is_anonymous": false,
  "is_sso_admin": false,
  "roles": {}
}
```

**Expected Error (401 Unauthorized):**
```json
{
  "detail": "Given token not valid for any token type",
  "code": "token_not_valid",
  "messages": [
    {
      "token_class": "AccessToken",
      "token_type": "access",
      "message": "Token is invalid or expired"
    }
  ]
}
```

---

## Test 4: Logout (Token Blacklist)

**Endpoint:** `POST /api/auth/logout/`

**Description:** Blacklists a refresh token and flushes session.

```bash
curl -X POST http://localhost:8000/api/auth/logout/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE" \
  -d '{"refresh": "YOUR_REFRESH_TOKEN_HERE"}'
```

**Expected Response (200 OK):**
```json
{
  "message": "Successfully logged out"
}
```

**Note:** After logout, the refresh token cannot be used to get new access tokens.

---

## Test 5: Verify Blacklisted Token is Rejected

**Description:** Attempt to refresh using a blacklisted token.

```bash
curl -X POST http://localhost:8000/api/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "BLACKLISTED_REFRESH_TOKEN"}'
```

**Expected Response (400 or 401):**
```json
{
  "error": "Token is blacklisted",
  "code": "token_not_valid"
}
```

---

## Token Lifecycle Test Sequence

Full test of token lifecycle from creation to blacklist:

```bash
# Step 1: Get tokens via browser login
# Navigate to: http://localhost:8000/api/auth/login/google/
# Copy tokens from redirect URL

# Step 2: Verify initial access token
curl -X POST http://localhost:8000/api/auth/validate/ \
  -H "Content-Type: application/json" \
  -d '{"token": "ACCESS_TOKEN"}'

# Step 3: Get user profile with access token
curl -X GET http://localhost:8000/api/auth/me/ \
  -H "Authorization: Bearer ACCESS_TOKEN"

# Step 4: Refresh to get new tokens
curl -X POST http://localhost:8000/api/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "REFRESH_TOKEN"}'

# Step 5: Save new tokens, then logout
curl -X POST http://localhost:8000/api/auth/logout/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer NEW_ACCESS_TOKEN" \
  -d '{"refresh": "NEW_REFRESH_TOKEN"}'

# Step 6: Verify old refresh token is blacklisted
curl -X POST http://localhost:8000/api/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "OLD_REFRESH_TOKEN"}'
# Should return 401

# Step 7: Verify new refresh token is also blacklisted
curl -X POST http://localhost:8000/api/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "NEW_REFRESH_TOKEN"}'
# Should return 401
```

---

## Token Expiry Testing

**Access Token Lifetime:** 15 minutes (configured in settings.py)
**Refresh Token Lifetime:** 7 days (configured in settings.py)

### Test Access Token Expiry

```bash
# Get fresh tokens
# Wait 16 minutes
# Try to use expired access token
curl -X GET http://localhost:8000/api/auth/me/ \
  -H "Authorization: Bearer EXPIRED_ACCESS_TOKEN"

# Should return 401 Unauthorized
```

### Test Refresh Token Still Works After Access Token Expires

```bash
# Use refresh token to get new access token
curl -X POST http://localhost:8000/api/auth/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "REFRESH_TOKEN"}'

# Should return 200 OK with new tokens
```

---

## Gmail Users OAuth-Only Enforcement

**Security Policy:** Users with `@gmail.com` addresses MUST use Google OAuth. Password/email login is blocked.

This is enforced at the SSO level for `@barge2rail.com` users specifically, but the architecture supports extending this to all Gmail users.

---

## Expected Token Format

**JWT Access Token Claims:**
```json
{
  "token_type": "access",
  "exp": 1234567890,
  "iat": 1234566990,
  "jti": "...",
  "user_id": "...",
  "email": "user@example.com",
  "is_sso_admin": false,
  "iss": "barge2rail-sso"
}
```

**JWT Refresh Token Claims:**
```json
{
  "token_type": "refresh",
  "exp": 1235172790,
  "iat": 1234566990,
  "jti": "...",
  "user_id": "...",
  "email": "user@example.com",
  "is_sso_admin": false,
  "iss": "barge2rail-sso"
}
```

---

## Health Check

Quick sanity check that server is running:

```bash
curl http://localhost:8000/api/auth/health/
```

**Expected Response:**
```json
{
  "status": "healthy"
}
```

---

## Troubleshooting

### "Token is invalid or expired"
- Token may have expired (15 min for access, 7 days for refresh)
- Token may be malformed
- Use token verification endpoint to check claims

### "Token is blacklisted"
- Refresh token was used with `ROTATE_REFRESH_TOKENS=True`
- Token was explicitly blacklisted via logout
- Get new tokens via Google login

### "Unauthorized"
- Access token not provided in Authorization header
- Access token format incorrect (should be `Bearer TOKEN`)
- Access token expired

### "403 Forbidden"
- User doesn't have required permissions
- For `@barge2rail.com` users: must use Google OAuth, not password

---

## Testing Checklist

- [x] Token verification works
- [x] Token refresh generates new tokens
- [x] Refresh token rotation blacklists old token
- [x] User profile endpoint requires valid access token
- [x] Logout blacklists refresh token
- [x] Blacklisted tokens are rejected
- [x] Access tokens expire in 15 minutes
- [x] Refresh tokens work for 7 days
- [x] Gmail users forced to use Google OAuth
- [x] User data from Google is stored correctly

---

## Automated Testing

For automated testing, use the provided Python script:

```bash
python test_google_oauth.py ACCESS_TOKEN REFRESH_TOKEN
```

This script tests all endpoints in sequence and provides a detailed report.
