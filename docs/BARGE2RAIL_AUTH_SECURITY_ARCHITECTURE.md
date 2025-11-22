# barge2rail-auth Security Architecture v2.0
**Project:** Django SSO Security Remediation  
**Version:** 2.0 (Blocker Fixes Integrated)  
**Created:** November 21, 2025  
**Status:** CONDITIONAL GO - Ready for Implementation After Blocker Fixes

---

## EXECUTIVE SUMMARY

**Original Vulnerabilities:**
1. HIGH: OAuth tokens exposed in URL query strings
2. HIGH: Unauthenticated token exchange endpoint  
3. HIGH: Session keys logged at INFO level
4. MEDIUM: JWT signing uses shared Django SECRET_KEY

**Security Enhancements Added (v2.0):**
- ✅ PKCE (Proof Key for Code Exchange) for OAuth flow
- ✅ Django CSRF protection for cookie-based authentication
- ✅ Proper cookie configuration (SameSite=Lax for OAuth compatibility)
- ✅ Token exchange endpoint removed entirely
- ✅ Concrete key rotation procedures with overlap support

**Deployment Strategy:**
- Staging first: `https://dashboard.render.com/web/srv-d479pummcj7s73d89qq0`
- Production after validation: `sso.barge2rail.com`
- HIGH RISK protocol with 4-week parallel operation

---

## CURRENT (VULNERABLE) ARCHITECTURE

### System Overview
**Technology Stack:**
- Django 4.2+ with django-oauth-toolkit
- Google OAuth 2.0 for authentication
- PostgreSQL via Neon (production database)
- JWT tokens via djangorestframework-simplejwt
- Deployed on Render with custom domain (sso.barge2rail.com)

**Current Authentication Flow (Vulnerable):**
```
1. User clicks "Login with Google"
2. Frontend redirects to Google OAuth consent screen
3. User approves access
4. Google redirects to callback URL with authorization code
5. Frontend extracts code from URL
6. Frontend sends code to backend API
7. Backend exchanges code for tokens
8. Backend returns tokens IN URL QUERY STRING ⚠️
9. Frontend stores tokens in localStorage
10. Subsequent API calls use access token from localStorage
```

### Vulnerability Details

**Vulnerability 1: OAuth Tokens in URL Query Strings (HIGH)**
- **Location:** OAuth callback returns tokens via URL parameters
- **Risk:** Browser history, server logs, referrer headers capture tokens
- **Attack Vector:** XSS, browser history access, log mining
- **Impact:** Complete account takeover if token leaked

**Vulnerability 2: Unauthenticated Token Exchange (HIGH)**
- **Location:** `/api/auth/exchange/` endpoint
- **Risk:** Anyone with authorization code can exchange for tokens
- **Attack Vector:** CSRF, session fixation, code theft
- **Impact:** Attacker can authenticate as victim

**Vulnerability 3: Session Keys in Logs (HIGH)**
- **Location:** Django session middleware logs session_key at INFO level
- **Risk:** Session keys appear in Render logs, accessible to attackers
- **Attack Vector:** Log access → session hijacking
- **Impact:** Complete session takeover

**Vulnerability 4: Shared JWT Signing Key (MEDIUM)**
- **Location:** JWT tokens signed with Django SECRET_KEY
- **Risk:** Same key used for sessions, CSRF, JWT
- **Attack Vector:** Key compromise affects all security mechanisms
- **Impact:** System-wide authentication bypass

---

## FIXED (SECURE) ARCHITECTURE v2.0

### Overview of Security Improvements

**Core Fixes (v1.0):**
1. Backend Authorization Code exchange (not frontend)
2. HTTP-only secure cookies (not URLs)
3. Encrypted token storage at rest
4. Separate JWT signing key
5. Secure logging (no sensitive data)
6. Authentication required for all token operations

**Enhanced Security (v2.0 - Blocker Fixes):**
7. **PKCE** - Proof Key for Code Exchange
8. **Django CSRF Protection** - Full CSRF middleware
9. **SameSite=Lax Cookies** - Proper OAuth redirect handling
10. **No Token Exchange Endpoint** - Eliminated attack surface
11. **Key Rotation Procedures** - Documented overlap rotation

---

## BLOCKER FIX 1: PKCE IMPLEMENTATION

### What is PKCE?

**PKCE (Proof Key for Code Exchange)** - RFC 7636
- Industry standard since 2015
- Required by OAuth 2.1 specification (draft)
- Prevents authorization code interception attacks
- Originally designed for mobile apps, now recommended for all clients

### How PKCE Works

**Step 1: Client generates random code_verifier**
```python
import secrets
import hashlib
import base64

# Generate random 43-character string
code_verifier = base64.urlsafe_b64encode(
    secrets.token_bytes(32)
).decode('utf-8').rstrip('=')

# Example: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
```

**Step 2: Client derives code_challenge**
```python
# SHA256 hash of code_verifier
code_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode('utf-8')).digest()
).decode('utf-8').rstrip('=')

# Example: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
```

**Step 3: Client stores code_verifier in session**
```python
request.session['pkce_code_verifier'] = code_verifier
request.session['pkce_created_at'] = time.time()
```

**Step 4: Client sends code_challenge to authorization server**
```python
auth_url = (
    f"{GOOGLE_AUTH_URL}?"
    f"client_id={CLIENT_ID}&"
    f"redirect_uri={REDIRECT_URI}&"
    f"response_type=code&"
    f"scope=openid email profile&"
    f"state={state}&"
    f"code_challenge={code_challenge}&"
    f"code_challenge_method=S256"
)
```

**Step 5: Authorization server stores code_challenge with authorization code**

**Step 6: Client exchanges authorization code with code_verifier**
```python
token_response = requests.post(
    GOOGLE_TOKEN_URL,
    data={
        'code': authorization_code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
        'code_verifier': code_verifier  # ← PKCE verification
    }
)
```

**Step 7: Authorization server validates code_verifier**
```python
# Server recomputes code_challenge from received code_verifier
computed_challenge = base64.urlsafe_b64encode(
    hashlib.sha256(code_verifier.encode('utf-8')).digest()
).decode('utf-8').rstrip('=')

# Server compares with stored code_challenge
if computed_challenge != stored_challenge:
    raise ValidationError("PKCE validation failed")
```

### Why PKCE Prevents Attacks

**Attack Scenario Without PKCE:**
1. Attacker intercepts authorization code (e.g., via browser history)
2. Attacker exchanges code for tokens using client_secret
3. Attacker gains access to victim's account

**Defense With PKCE:**
1. Attacker intercepts authorization code
2. Attacker tries to exchange code for tokens
3. **Server rejects:** code_verifier doesn't match stored code_challenge
4. Only the original client (with code_verifier in session) can complete exchange

**Key Point:** code_verifier never leaves the client until token exchange, and is never in URLs or logs.

### PKCE Integration into Our Flow

**Updated OAuth Initiation (Step 1):**
```python
def initiate_oauth(request):
    """
    Step 1: Generate PKCE parameters and redirect to Google.
    """
    # Generate state (CSRF protection)
    state = secrets.token_urlsafe(32)

    # Generate PKCE code_verifier
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')

    # Derive code_challenge
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')

    # Store in session (server-side, never in cookies/URLs)
    request.session['oauth_state'] = state
    request.session['oauth_state_created_at'] = time.time()
    request.session['pkce_code_verifier'] = code_verifier
    request.session['pkce_created_at'] = time.time()

    # Build authorization URL with PKCE
    auth_url = (
        f"{settings.GOOGLE_AUTH_URL}?"
        f"client_id={settings.GOOGLE_CLIENT_ID}&"
        f"redirect_uri={settings.GOOGLE_REDIRECT_URI}&"
        f"response_type=code&"
        f"scope=openid email profile&"
        f"state={state}&"
        f"code_challenge={code_challenge}&"
        f"code_challenge_method=S256"  # ← Always use S256 (SHA256)
    )

    return redirect(auth_url)
```

**Updated Token Exchange (Step 10):**
```python
def oauth_callback(request):
    """
    Step 10: Exchange authorization code with PKCE verification.
    """
    # Validate state (existing CSRF protection)
    state = request.GET.get('state')
    stored_state = request.session.get('oauth_state')

    if not state or state != stored_state:
        return JsonResponse({'error': 'Invalid state'}, status=400)

    # Check state timeout (5 minutes)
    state_age = time.time() - request.session.get('oauth_state_created_at', 0)
    if state_age > 300:
        return JsonResponse({'error': 'State expired'}, status=400)

    # Retrieve PKCE code_verifier
    code_verifier = request.session.get('pkce_code_verifier')
    if not code_verifier:
        return JsonResponse({'error': 'PKCE verifier missing'}, status=400)

    # Check PKCE timeout (5 minutes)
    pkce_age = time.time() - request.session.get('pkce_created_at', 0)
    if pkce_age > 300:
        return JsonResponse({'error': 'PKCE verifier expired'}, status=400)

    # Exchange authorization code with PKCE
    authorization_code = request.GET.get('code')

    token_response = requests.post(
        settings.GOOGLE_TOKEN_URL,
        data={
            'code': authorization_code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code',
            'code_verifier': code_verifier  # ← PKCE verification
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )

    if token_response.status_code != 200:
        return JsonResponse({'error': 'Token exchange failed'}, status=400)

    tokens = token_response.json()

    # Clear PKCE parameters from session (single use)
    del request.session['pkce_code_verifier']
    del request.session['pkce_created_at']
    del request.session['oauth_state']
    del request.session['oauth_state_created_at']

    # Continue with token storage and JWT issuance...
```

### PKCE Security Benefits

✅ **Authorization Code Interception Protection**
- Even if attacker steals authorization code, cannot exchange without code_verifier
- code_verifier never in URLs, only in server-side session

✅ **Defense in Depth**
- Complements state parameter (CSRF protection)
- Adds cryptographic binding between authorization request and token request

✅ **OAuth 2.1 Compliance**
- Required by draft OAuth 2.1 specification
- Industry best practice for all OAuth flows

✅ **No Additional User Friction**
- Completely transparent to end users
- No additional prompts or confirmations needed

---

## BLOCKER FIX 2: DJANGO CSRF PROTECTION

### Why CSRF Protection is Required

**Cookie-Based Authentication = CSRF Vulnerable**

Our architecture uses HTTP-only cookies for JWT tokens:
```python
response.set_cookie(
    'jwt_token',
    jwt_value,
    httponly=True,  # ← JavaScript cannot access
    secure=True,
    samesite='Lax'
)
```

**Problem:** Browsers automatically send cookies with every request to domain
```html
<!-- Attacker's malicious site -->
<form action="https://sso.barge2rail.com/api/users/delete" method="POST">
    <input type="hidden" name="user_id" value="victim">
</form>
<script>document.forms[0].submit();</script>
```

**Without CSRF Protection:**
1. User visits attacker's site (while logged into barge2rail.com)
2. Attacker's form submits POST to barge2rail.com
3. Browser automatically includes jwt_token cookie
4. Backend sees valid JWT, processes request
5. **Victim's data deleted** ⚠️

**With CSRF Protection:**
1. User visits attacker's site
2. Attacker's form submits POST to barge2rail.com
3. Browser includes jwt_token cookie
4. **Backend rejects: missing CSRF token** ✅
5. Attack prevented

### Django CSRF Middleware Configuration

**settings.py:**
```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # ← MUST be enabled
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# CSRF Configuration
CSRF_COOKIE_SECURE = True  # HTTPS only
CSRF_COOKIE_HTTPONLY = False  # JavaScript MUST read this
CSRF_COOKIE_SAMESITE = 'Lax'  # Match JWT cookie
CSRF_COOKIE_NAME = 'csrftoken'
CSRF_HEADER_NAME = 'HTTP_X_CSRFTOKEN'
CSRF_TRUSTED_ORIGINS = [
    'https://sso.barge2rail.com',
    'https://app.barge2rail.com',
]
```

### How CSRF Protection Works

**Step 1: Backend sets CSRF cookie on login**
```python
def oauth_callback(request):
    # ... exchange authorization code for tokens ...

    # Issue JWT in HTTP-only cookie
    response = redirect('/dashboard')
    response.set_cookie(
        'jwt_token',
        jwt_value,
        httponly=True,
        secure=True,
        samesite='Lax'
    )

    # Django automatically sets CSRF cookie (via middleware)
    # Cookie name: 'csrftoken'
    # HttpOnly: False (JavaScript can read)
    # Value: Random 64-character token

    return response
```

**Step 2: Frontend reads CSRF token from cookie**
```javascript
// Frontend utility function
function getCsrfToken() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'csrftoken') {
            return value;
        }
    }
    return null;
}
```

**Step 3: Frontend includes CSRF token in request headers**
```javascript
// POST/PUT/PATCH/DELETE requests
fetch('https://sso.barge2rail.com/api/users/', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCsrfToken()  // ← CSRF token in header
    },
    credentials: 'include',  // ← Sends jwt_token cookie
    body: JSON.stringify({ name: 'John Doe', email: 'john@example.com' })
})
```

**Step 4: Backend validates CSRF token**
```python
# Django CSRF middleware automatically:
# 1. Extracts CSRF token from 'X-CSRFToken' header
# 2. Compares with CSRF token from cookie
# 3. Rejects if mismatch or missing

@csrf_protect  # ← Decorator enforces CSRF validation
def create_user(request):
    # If we reach here, CSRF validation passed ✅
    data = json.loads(request.body)
    user = User.objects.create(**data)
    return JsonResponse({'id': user.id})
```

### CSRF Exemptions (Rare Cases Only)

**When to Exempt:**
- Public webhooks (external services can't get CSRF token)
- API endpoints with non-cookie authentication (e.g., Bearer tokens)

**How to Exempt (Use Sparingly):**
```python
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def webhook_receiver(request):
    """
    Webhook from external service (e.g., Stripe, SendGrid).

    CSRF protection not applicable - no cookies used.
    Must validate webhook signature instead.
    """
    signature = request.headers.get('X-Webhook-Signature')
    if not validate_webhook_signature(signature, request.body):
        return JsonResponse({'error': 'Invalid signature'}, status=403)

    # Process webhook...
```

### CSRF Attack Prevention Summary

✅ **Double Cookie Defense**
- CSRF token in cookie (httponly=False, readable by JavaScript)
- JWT token in cookie (httponly=True, NOT readable by JavaScript)
- Attacker cannot read either cookie via JavaScript (SOP protection)

✅ **Cross-Origin Protection**
- Attacker's site at evil.com cannot read cookies from barge2rail.com
- Even if form submits to barge2rail.com, missing CSRF token fails

✅ **State Changing Operations Protected**
- POST/PUT/PATCH/DELETE require CSRF token
- GET requests exempt (should be read-only anyway)

---

## BLOCKER FIX 3: SameSite=Lax (Not Strict)

### Why SameSite=Strict Breaks OAuth

**OAuth Flow Requires Cross-Site Redirects:**

```
1. User at app.barge2rail.com clicks "Login"
2. Redirects to sso.barge2rail.com/oauth/authorize
3. User approves
4. Google redirects to sso.barge2rail.com/oauth/callback  ← CROSS-SITE
5. Backend sets JWT cookie
6. Redirects to app.barge2rail.com/dashboard
```

**Problem with SameSite=Strict:**
```python
response.set_cookie(
    'jwt_token',
    jwt_value,
    samesite='Strict'  # ← PROBLEM
)
```

**Step 4 (Google → sso.barge2rail.com):** Browser sees cross-site request from google.com → Does NOT send jwt_token cookie

**Result:** User appears logged out after OAuth flow completes ⚠️

### SameSite Options Explained

**SameSite=Strict:**
- Cookie ONLY sent on same-site requests
- Never sent on cross-site requests (even safe GET)
- **Breaks OAuth redirects** ❌

**SameSite=Lax (Recommended):**
- Cookie sent on same-site requests ✅
- Cookie sent on top-level cross-site GET requests ✅
- Cookie NOT sent on cross-site POST/embedded requests ✅
- **OAuth redirects work** ✅
- **CSRF attacks still blocked** ✅

**SameSite=None:**
- Cookie sent on ALL requests (same-site and cross-site)
- Must use with Secure=True (HTTPS only)
- **Too permissive for our use case** ❌

### Correct Cookie Configuration

```python
def set_auth_cookies(response, jwt_token):
    """
    Set JWT cookie with SameSite=Lax.

    Allows OAuth redirects while maintaining CSRF protection.
    """
    response.set_cookie(
        'jwt_token',
        jwt_token,
        max_age=3600,  # 1 hour
        httponly=True,  # JavaScript cannot read
        secure=True,  # HTTPS only
        samesite='Lax',  # ← OAuth-compatible
        domain='.barge2rail.com'  # Shared across subdomains
    )

    # CSRF cookie (Django sets automatically, but shown for clarity)
    response.set_cookie(
        'csrftoken',
        csrf_token,
        httponly=False,  # JavaScript can read
        secure=True,
        samesite='Lax',  # ← Match JWT cookie
        domain='.barge2rail.com'
    )

    return response
```

### Why SameSite=Lax Still Prevents CSRF

**CSRF Attack Scenario:**
```html
<!-- Attacker's site: evil.com -->
<form action="https://sso.barge2rail.com/api/users/delete" method="POST">
    <input type="hidden" name="user_id" value="victim">
</form>
<script>document.forms[0].submit();</script>
```

**With SameSite=Lax:**
1. Form submits POST from evil.com → sso.barge2rail.com
2. Browser sees: Cross-site POST request
3. **Browser does NOT send jwt_token cookie** ✅
4. Backend rejects: No authentication
5. Attack prevented

**Why OAuth Redirects Still Work:**
```
1. Google redirects to sso.barge2rail.com/oauth/callback (GET request)
2. Browser sees: Top-level cross-site GET
3. **Browser DOES send jwt_token cookie** ✅
4. OAuth flow completes successfully
```

**Key Difference:**
- Top-level GET (OAuth redirect): Cookie sent ✅
- Cross-site POST (CSRF attack): Cookie NOT sent ✅

### Defense In Depth: SameSite + CSRF Token

**Both Protections Active:**
1. **SameSite=Lax:** Blocks cookies on cross-site POST
2. **CSRF Token:** Requires attacker know token value

**Attacker Must Bypass Both:**
- Get cookie sent (can't, SameSite=Lax blocks cross-site POST)
- AND know CSRF token (can't, different origin)

**Result:** Double defense against CSRF attacks ✅

---

## BLOCKER FIX 4: TOKEN EXCHANGE ENDPOINT REMOVAL

### Why Token Exchange Endpoint Was Vulnerable

**Original Architecture (v1.0):**
```python
# Vulnerable endpoint
@api_view(['POST'])
def exchange_token(request):
    """
    Exchange authorization code for tokens.

    VULNERABILITY: No authentication required.
    Anyone with code can exchange for tokens.
    """
    code = request.data.get('code')

    # Exchange with Google (UNAUTHENTICATED)
    token_response = requests.post(...)

    return Response({
        'access_token': tokens['access_token'],
        'refresh_token': tokens['refresh_token']
    })
```

**Attack Scenarios:**

**Attack 1: Authorization Code Theft**
1. Attacker intercepts authorization code (browser history, logs, etc.)
2. Attacker calls `/api/auth/exchange/` with stolen code
3. Attacker receives tokens for victim's account
4. Account takeover ⚠️

**Attack 2: CSRF on Token Exchange**
1. Attacker tricks user into visiting malicious page
2. Page submits form to `/api/auth/exchange/` with attacker's code
3. Victim's session now linked to attacker's account
4. Session fixation attack ⚠️

### Secure Architecture: No Separate Exchange Endpoint

**New Flow (v2.0):**
```python
# Single endpoint handles entire OAuth flow
@csrf_protect  # ← CSRF protected
def oauth_callback(request):
    """
    Handle OAuth callback - exchange + storage + JWT issuance.

    SECURE: Everything happens in one authenticated flow.
    No separate endpoint = no separate attack surface.
    """
    # Step 1: Validate state (CSRF protection)
    state = request.GET.get('state')
    if state != request.session.get('oauth_state'):
        return JsonResponse({'error': 'Invalid state'}, status=400)

    # Step 2: Validate PKCE verifier
    code_verifier = request.session.get('pkce_code_verifier')
    if not code_verifier:
        return JsonResponse({'error': 'Missing PKCE verifier'}, status=400)

    # Step 3: Exchange authorization code (server-to-server)
    code = request.GET.get('code')
    token_response = requests.post(
        settings.GOOGLE_TOKEN_URL,
        data={
            'code': code,
            'client_id': settings.GOOGLE_CLIENT_ID,
            'client_secret': settings.GOOGLE_CLIENT_SECRET,
            'redirect_uri': settings.GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code',
            'code_verifier': code_verifier  # ← PKCE
        }
    )

    if token_response.status_code != 200:
        return JsonResponse({'error': 'Exchange failed'}, status=400)

    tokens = token_response.json()

    # Step 4: Store refresh token (encrypted)
    encrypted_refresh = encrypt_token(tokens['refresh_token'])
    OAuthToken.objects.create(
        user=user,
        refresh_token=encrypted_refresh,
        expires_at=timezone.now() + timedelta(days=30)
    )

    # Step 5: Issue JWT in HTTP-only cookie
    jwt_token = create_jwt(user)
    response = redirect('/dashboard')
    response.set_cookie(
        'jwt_token',
        jwt_token,
        httponly=True,
        secure=True,
        samesite='Lax'
    )

    return response
```

### Attack Prevention Analysis

**Authorization Code Theft:**
- ❌ **v1.0:** Stolen code → call `/api/auth/exchange/` → tokens
- ✅ **v2.0:** Stolen code → call `oauth_callback` → state validation fails (attacker doesn't have state in session)

**PKCE Protection:**
- ❌ **v1.0:** No PKCE → authorization code alone sufficient
- ✅ **v2.0:** PKCE required → attacker needs code_verifier from victim's session (impossible to get)

**CSRF on Token Exchange:**
- ❌ **v1.0:** Separate endpoint → CSRF possible → session fixation
- ✅ **v2.0:** No separate endpoint → state parameter validates → CSRF not possible

**Key Security Principle:** Minimize attack surface
- Fewer endpoints = fewer vulnerabilities
- OAuth callback handles everything = single point of validation

---

## BLOCKER FIX 5: JWT KEY ROTATION PROCEDURES

### Why Key Rotation Matters

**JWT Signing Key Compromise Scenarios:**
1. Developer accidentally commits key to git
2. Server logs expose environment variables
3. Employee leaves company with key access
4. Security audit recommends key rotation
5. Compliance requirement (rotate every 90 days)

**Without Rotation Procedure:**
- Manual key update = downtime
- All users logged out simultaneously
- Emergency rotation = chaos

**With Rotation Procedure:**
- Zero-downtime key rotation
- Gradual user migration
- No emergency panic

### Overlap Rotation Strategy

**Concept:** Support TWO keys simultaneously during transition
```
Week 1: KEY_V1 (signing + validating)
Week 2: KEY_V1 + KEY_V2 (both validating, V2 signing)
Week 3: KEY_V2 (signing + validating), V1 deprecated
```

**Benefits:**
- Zero downtime
- Users with old JWTs still work
- Gradual migration over 1 week
- Rollback possible if issues

### Implementation: Multi-Key Support

**Environment Variables:**
```bash
# JWT Key Configuration
JWT_SIGNING_KEY_V1=<current-key>  # Old key (week 1-2)
JWT_SIGNING_KEY_V2=<new-key>      # New key (week 2-3)
JWT_KEY_VERSION=1                 # Active version (1 or 2)
```

**Key Generation Command:**
```python
# management/commands/generate_jwt_key.py
from django.core.management.base import BaseCommand
import secrets

class Command(BaseCommand):
    help = 'Generate new JWT signing key'

    def handle(self, *args, **options):
        # Generate 256-bit key (32 bytes)
        key = secrets.token_urlsafe(32)

        self.stdout.write(f'Generated JWT signing key:\n{key}')
        self.stdout.write('\nAdd to environment variables:')
        self.stdout.write(f'JWT_SIGNING_KEY_V2={key}')
```

**Settings Configuration:**
```python
# settings.py
JWT_SIGNING_KEY_V1 = env('JWT_SIGNING_KEY_V1', default=None)
JWT_SIGNING_KEY_V2 = env('JWT_SIGNING_KEY_V2', default=None)
JWT_KEY_VERSION = env.int('JWT_KEY_VERSION', default=1)

# Validation: Ensure at least one key exists
if not JWT_SIGNING_KEY_V1 and not JWT_SIGNING_KEY_V2:
    raise ImproperlyConfigured('At least one JWT signing key required')

# Active key for signing
JWT_SIGNING_KEY = JWT_SIGNING_KEY_V2 if JWT_KEY_VERSION == 2 else JWT_SIGNING_KEY_V1

# All keys for validation (support both during overlap)
JWT_VALIDATION_KEYS = [k for k in [JWT_SIGNING_KEY_V1, JWT_SIGNING_KEY_V2] if k]
```

**JWT Creation (Always Uses Active Key):**
```python
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

def create_jwt(user):
    """
    Create JWT signed with active key version.
    """
    refresh = RefreshToken.for_user(user)

    # Add custom claims
    refresh['email'] = user.email
    refresh['key_version'] = settings.JWT_KEY_VERSION  # ← Track which key signed this

    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh)
    }
```

**JWT Validation (Accepts Any Valid Key):**
```python
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from django.conf import settings
import jwt

class MultiKeyJWTAuthentication(JWTAuthentication):
    """
    JWT authentication supporting multiple keys.

    Tries all validation keys until one succeeds.
    """

    def get_validated_token(self, raw_token):
        """
        Validate token against all available keys.
        """
        errors = []

        # Try each validation key
        for key in settings.JWT_VALIDATION_KEYS:
            try:
                # Attempt validation with this key
                return jwt.decode(
                    raw_token,
                    key,
                    algorithms=['HS256'],
                    options={'verify_signature': True}
                )
            except jwt.InvalidSignatureError as e:
                errors.append(f'Key validation failed: {str(e)}')
                continue  # Try next key
            except jwt.ExpiredSignatureError:
                raise InvalidToken('Token expired')
            except jwt.DecodeError:
                raise InvalidToken('Token decode failed')

        # All keys failed
        raise InvalidToken(f'All key validations failed: {errors}')
```

### Step-by-Step Rotation Procedure

**See:** `JWT_KEY_ROTATION_PROCEDURE.md` for detailed step-by-step guide

**Summary:**
1. **Week 1:** Generate new key (V2), keep current key (V1) active
2. **Week 2:** Deploy with both keys, switch active to V2
3. **Week 3:** Monitor JWTs, deprecate V1 when all migrated
4. **Week 4:** Remove V1 from environment

**Emergency Rotation (Compromise Detected):**
1. Generate new key immediately
2. Deploy with JWT_KEY_VERSION=2
3. Invalidate all existing sessions (force re-login)
4. Rotate within 1 hour

---

## COMPLETE SECURE AUTHENTICATION FLOW v2.0

### Full Flow with All Security Enhancements

```
1. User clicks "Login with Google" → Frontend
   ↓
2. Frontend → Backend: POST /api/auth/initiate/
   ↓
3. Backend generates:
   - state (CSRF protection)
   - code_verifier (PKCE)
   - code_challenge = SHA256(code_verifier)
   ↓
4. Backend stores in session:
   - oauth_state
   - oauth_state_created_at
   - pkce_code_verifier
   - pkce_created_at
   ↓
5. Backend → Frontend: Returns Google OAuth URL with:
   - client_id
   - redirect_uri
   - response_type=code
   - scope=openid email profile
   - state
   - code_challenge
   - code_challenge_method=S256
   ↓
6. Frontend redirects to Google OAuth URL
   ↓
7. User authenticates at Google, approves permissions
   ↓
8. Google → Backend: Redirect to callback URL with:
   - code (authorization code)
   - state
   ↓
9. Backend validates state:
   - Exists in session ✅
   - Matches request parameter ✅
   - Created < 5 minutes ago ✅
   ↓
10. Backend retrieves PKCE code_verifier from session:
    - Exists ✅
    - Created < 5 minutes ago ✅
    ↓
11. Backend → Google: POST /token (server-to-server)
    - code (authorization code)
    - client_id
    - client_secret (never exposed to browser)
    - redirect_uri
    - grant_type=authorization_code
    - code_verifier (PKCE proof)
    ↓
12. Google validates:
    - Authorization code ✅
    - Client credentials ✅
    - PKCE: SHA256(code_verifier) == stored code_challenge ✅
    ↓
13. Google → Backend: Returns:
    - access_token
    - refresh_token
    - id_token (optional)
    - expires_in
    ↓
14. Backend creates/updates Django user from Google profile
    ↓
15. Backend stores ONLY refresh_token (encrypted):
    - Encrypt with TOKEN_ENCRYPTION_KEY (Fernet)
    - Store in OAuthToken model
    - Associate with user
    ↓
16. Backend generates JWT (signed with active key):
    - User ID
    - Email
    - Key version
    - Expiration (1 hour)
    - Signed with JWT_SIGNING_KEY (separate from Django SECRET_KEY)
    ↓
17. Backend → Frontend: Redirect to /dashboard with JWT cookie:
    - httponly=True (JavaScript cannot read)
    - secure=True (HTTPS only)
    - samesite='Lax' (OAuth-compatible + CSRF protection)
    - domain='.barge2rail.com' (shared across subdomains)
    ↓
18. Backend automatically sets CSRF cookie (Django middleware):
    - httponly=False (JavaScript CAN read)
    - secure=True
    - samesite='Lax'
    ↓
19. Frontend receives redirect:
    - Cookies set automatically by browser
    - No JavaScript interaction needed
    ↓
20. Frontend → Backend: GET /api/auth/status/
    - Browser automatically sends jwt_token cookie
    ↓
21. Backend validates JWT from cookie:
    - Extracts from HTTP-only cookie
    - Tries validation with all JWT_VALIDATION_KEYS
    - Verifies signature, expiration, claims
    ↓
22. Backend → Frontend: Returns user info (JSON)
    ↓
23. User authenticated! ✅
    ↓
24. Subsequent API requests:
    - Frontend makes API call
    - Browser automatically sends jwt_token cookie
    - For POST/PUT/PATCH/DELETE: Frontend reads csrftoken cookie (JavaScript)
    - Frontend includes X-CSRFToken header
    - Backend validates both JWT + CSRF token
    - Request proceeds if both valid ✅
```

### Security Checkpoints in Flow

**OAuth Initiation (Steps 1-5):**
- ✅ State generated (CSRF protection)
- ✅ PKCE code_verifier generated and stored securely
- ✅ Code_challenge derived via SHA256
- ✅ Both stored server-side (never in cookies/URLs)

**Google Callback (Steps 8-10):**
- ✅ State validated against session
- ✅ State timeout enforced (<5 minutes)
- ✅ PKCE code_verifier retrieved from session
- ✅ PKCE timeout enforced (<5 minutes)

**Token Exchange (Steps 11-13):**
- ✅ Server-to-server (client_secret never exposed)
- ✅ Code_verifier sent (PKCE proof)
- ✅ Google validates PKCE challenge matches
- ✅ Authorization code single-use

**Token Storage (Step 15):**
- ✅ Only refresh token stored (not access token)
- ✅ Encrypted with separate key (Fernet symmetric encryption)
- ✅ Associated with user in database

**JWT Issuance (Steps 16-18):**
- ✅ Signed with dedicated JWT key (not Django SECRET_KEY)
- ✅ Short-lived (1 hour expiration)
- ✅ HTTP-only cookie (XSS protection)
- ✅ SameSite=Lax (CSRF + OAuth compatible)
- ✅ Secure flag (HTTPS only)
- ✅ CSRF cookie set automatically (Django middleware)

**Request Validation (Steps 20-24):**
- ✅ JWT validated from HTTP-only cookie
- ✅ Multi-key validation (supports key rotation)
- ✅ CSRF token validated on state-changing requests
- ✅ Double defense (JWT + CSRF)

---

## ENVIRONMENT VARIABLES v2.0

```bash
# Django Core
SECRET_KEY=<django-secret-key>  # Keep separate from JWT
DEBUG=False

# Database
DATABASE_URL=<neon-postgresql-url>

# Google OAuth
GOOGLE_CLIENT_ID=<your-client-id>
GOOGLE_CLIENT_SECRET=<your-client-secret>
GOOGLE_AUTH_URL=https://accounts.google.com/o/oauth2/v2/auth
GOOGLE_TOKEN_URL=https://oauth2.googleapis.com/token
GOOGLE_REDIRECT_URI=https://sso.barge2rail.com/api/auth/callback/

# JWT Configuration (BLOCKER 5: Key Rotation Support)
JWT_SIGNING_KEY_V1=<generate-with-management-command>  # Current/old key
JWT_SIGNING_KEY_V2=<generate-with-management-command>  # New key (during rotation)
JWT_KEY_VERSION=1  # Active version (1 or 2)

# Token Encryption
TOKEN_ENCRYPTION_KEY=<generate-with-fernet>

# Application URLs
FRONTEND_URL=https://app.barge2rail.com
BACKEND_URL=https://sso.barge2rail.com

# Cookie Configuration (BLOCKER 3)
COOKIE_DOMAIN=.barge2rail.com

# CSRF Configuration (BLOCKER 2)
CSRF_TRUSTED_ORIGINS=https://sso.barge2rail.com,https://app.barge2rail.com

# Deployment
RENDER_EXTERNAL_URL=https://sso.barge2rail.com
```

### Key Generation Commands

```bash
# Generate JWT signing keys (run twice for V1 and V2)
python manage.py generate_jwt_key

# Generate token encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## DATABASE SCHEMA v2.0

### Django Models

**User Model (Existing):**
```python
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """
    Extended user model with Google OAuth support.
    """
    email = models.EmailField(unique=True)
    google_id = models.CharField(max_length=255, unique=True, null=True)
    profile_picture = models.URLField(null=True, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
```

**OAuth Token Storage (NEW):**
```python
from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet

class OAuthToken(models.Model):
    """
    Encrypted OAuth refresh tokens.

    Security:
    - Only refresh tokens stored (not access tokens)
    - Encrypted at rest with Fernet (symmetric)
    - Automatic expiration tracking
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='oauth_token'
    )

    # Encrypted refresh token
    refresh_token = models.TextField()  # Fernet encrypted

    # Expiration tracking
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def set_refresh_token(self, token):
        """Encrypt and store refresh token."""
        fernet = Fernet(settings.TOKEN_ENCRYPTION_KEY.encode())
        encrypted = fernet.encrypt(token.encode())
        self.refresh_token = encrypted.decode()

    def get_refresh_token(self):
        """Decrypt and return refresh token."""
        fernet = Fernet(settings.TOKEN_ENCRYPTION_KEY.encode())
        decrypted = fernet.decrypt(self.refresh_token.encode())
        return decrypted.decode()

    class Meta:
        db_table = 'oauth_tokens'
```

**PKCE State Storage (NEW - Session-Based):**
```python
# No database model needed - stored in Django session
# Session data:
# {
#     'oauth_state': 'random-state-token',
#     'oauth_state_created_at': 1700000000.0,
#     'pkce_code_verifier': 'random-verifier',
#     'pkce_created_at': 1700000000.0
# }

# Session expires after 5 minutes (enforced in view logic)
```

### Migrations

```python
# Generated migration file
from django.db import migrations, models

class Migration(migrations.Migration):
    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='OAuthToken',
            fields=[
                ('id', models.BigAutoField(primary_key=True)),
                ('refresh_token', models.TextField()),
                ('expires_at', models.DateTimeField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(
                    on_delete=models.deletion.CASCADE,
                    related_name='oauth_token',
                    to='auth.user'
                )),
            ],
            options={'db_table': 'oauth_tokens'},
        ),
    ]
```

---

## TESTING REQUIREMENTS v2.0

### Security Test Cases (NEW)

**PKCE Tests:**
```python
def test_pkce_code_verifier_generation():
    """Test PKCE code_verifier is cryptographically random."""
    verifier1 = generate_code_verifier()
    verifier2 = generate_code_verifier()

    assert len(verifier1) == 43  # Base64 URL-safe 32 bytes
    assert verifier1 != verifier2  # Each verifier unique

def test_pkce_code_challenge_derivation():
    """Test code_challenge correctly derived from verifier."""
    verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    expected_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

    challenge = generate_code_challenge(verifier)
    assert challenge == expected_challenge

def test_pkce_timeout_enforcement():
    """Test PKCE verifier expires after 5 minutes."""
    # Store verifier with old timestamp
    session['pkce_code_verifier'] = 'test-verifier'
    session['pkce_created_at'] = time.time() - 301  # 5 min 1 sec ago

    response = oauth_callback(request)
    assert response.status_code == 400
    assert 'PKCE verifier expired' in response.content
```

**CSRF Tests:**
```python
def test_csrf_protection_on_post():
    """Test POST requests require CSRF token."""
    client = Client(enforce_csrf_checks=True)

    # POST without CSRF token
    response = client.post('/api/users/', {'name': 'Test'})
    assert response.status_code == 403  # CSRF verification failed

    # POST with CSRF token
    csrf_token = client.cookies['csrftoken'].value
    response = client.post(
        '/api/users/',
        {'name': 'Test'},
        HTTP_X_CSRFTOKEN=csrf_token
    )
    assert response.status_code == 201  # Success

def test_csrf_cookie_set_on_login():
    """Test CSRF cookie automatically set on login."""
    response = oauth_callback_success(request)

    assert 'csrftoken' in response.cookies
    assert response.cookies['csrftoken']['secure'] is True
    assert response.cookies['csrftoken']['samesite'] == 'Lax'
```

**SameSite Tests:**
```python
def test_samesite_lax_on_jwt_cookie():
    """Test JWT cookie uses SameSite=Lax."""
    response = oauth_callback_success(request)

    jwt_cookie = response.cookies['jwt_token']
    assert jwt_cookie['samesite'] == 'Lax'  # Not Strict
    assert jwt_cookie['httponly'] is True
    assert jwt_cookie['secure'] is True

def test_oauth_redirect_with_samesite_lax():
    """Test OAuth redirect works with SameSite=Lax."""
    # Simulate Google redirect (cross-site GET)
    request = RequestFactory().get(
        '/api/auth/callback/',
        {'code': 'auth-code', 'state': 'valid-state'},
        HTTP_REFERER='https://accounts.google.com'
    )

    # Cookie should be sent (Lax allows top-level GET)
    response = oauth_callback(request)
    assert response.status_code == 302  # Successful redirect
```

**No Token Exchange Endpoint Tests:**
```python
def test_no_separate_token_exchange_endpoint():
    """Test /api/auth/exchange/ endpoint does not exist."""
    response = client.post('/api/auth/exchange/', {'code': 'test'})
    assert response.status_code == 404  # Endpoint removed

def test_oauth_callback_handles_complete_flow():
    """Test oauth_callback handles exchange + storage + JWT issuance."""
    response = oauth_callback(request)

    # Verify all steps completed in one endpoint
    assert 'jwt_token' in response.cookies  # JWT issued
    assert OAuthToken.objects.filter(user=user).exists()  # Token stored
    assert response.status_code == 302  # Redirect to app
```

**Key Rotation Tests:**
```python
def test_jwt_signed_with_active_key():
    """Test JWT signed with key specified by JWT_KEY_VERSION."""
    with override_settings(JWT_KEY_VERSION=2):
        jwt = create_jwt(user)
        decoded = jwt.decode(jwt, settings.JWT_SIGNING_KEY_V2, algorithms=['HS256'])
        assert decoded['key_version'] == 2

def test_jwt_validates_with_any_key():
    """Test JWT validates against any key in JWT_VALIDATION_KEYS."""
    # Create JWT with V1
    with override_settings(JWT_KEY_VERSION=1):
        jwt_v1 = create_jwt(user)

    # Validate with both V1 and V2 available
    with override_settings(JWT_VALIDATION_KEYS=[KEY_V1, KEY_V2]):
        decoded = validate_jwt(jwt_v1)
        assert decoded['email'] == user.email

def test_emergency_key_rotation():
    """Test all JWTs invalidated on emergency rotation."""
    # Create JWT with V1
    jwt_v1 = create_jwt(user)

    # Emergency rotation: Remove V1, activate V2
    with override_settings(
        JWT_KEY_VERSION=2,
        JWT_VALIDATION_KEYS=[KEY_V2]  # Only V2
    ):
        with pytest.raises(InvalidToken):
            validate_jwt(jwt_v1)  # V1 JWT now invalid
```

### Existing Test Coverage

**OAuth Flow Tests (40 existing tests):**
- ✅ State validation
- ✅ Token exchange success/failure
- ✅ User creation/update
- ✅ Session management
- ✅ Rate limiting

**Total Test Count v2.0:**
- Existing: 40 tests
- New security tests: 15+ tests
- **Total: 55+ comprehensive tests**

---

## DEPLOYMENT CHECKLIST v2.0

### Pre-Deployment

**Environment Variables:**
- [ ] `JWT_SIGNING_KEY_V1` generated and set
- [ ] `JWT_SIGNING_KEY_V2` generated (for future rotation)
- [ ] `JWT_KEY_VERSION=1` set
- [ ] `TOKEN_ENCRYPTION_KEY` generated and set
- [ ] `CSRF_TRUSTED_ORIGINS` includes all app domains
- [ ] `COOKIE_DOMAIN=.barge2rail.com` set

**Settings Verification:**
- [ ] `CSRF_COOKIE_SECURE=True`
- [ ] `CSRF_COOKIE_HTTPONLY=False`
- [ ] `CSRF_COOKIE_SAMESITE='Lax'`
- [ ] `SESSION_COOKIE_SECURE=True`
- [ ] `SESSION_COOKIE_SAMESITE='Lax'`
- [ ] `CsrfViewMiddleware` enabled in MIDDLEWARE

**Code Changes:**
- [ ] PKCE implementation complete (`initiate_oauth` + `oauth_callback`)
- [ ] Multi-key JWT validation (`MultiKeyJWTAuthentication`)
- [ ] Token exchange endpoint removed (`/api/auth/exchange/` deleted)
- [ ] SameSite=Lax on all auth cookies

**Database:**
- [ ] `OAuthToken` model migrated
- [ ] Encryption key backup stored securely (offline)

**Testing:**
- [ ] All 55+ tests passing
- [ ] Manual OAuth flow tested in staging
- [ ] CSRF protection verified (POST without token fails)
- [ ] Cookie configuration verified (DevTools inspection)

### Deployment Steps

**Staging Deploy:**
1. [ ] Deploy to Render staging environment
2. [ ] Run database migrations
3. [ ] Test complete OAuth flow (Google login)
4. [ ] Verify PKCE in network logs (code_challenge in authorize request)
5. [ ] Test CSRF protection (POST without X-CSRFToken header fails)
6. [ ] Verify cookies (SameSite=Lax, HttpOnly, Secure)
7. [ ] Test key rotation procedure (generate V2, switch active)

**Production Deploy (After 1 Week Staging):**
8. [ ] Deploy to production (`sso.barge2rail.com`)
9. [ ] Monitor error logs (first 24 hours)
10. [ ] Verify no CSRF errors in logs
11. [ ] Verify PKCE success rate (100%)
12. [ ] User feedback collection (authentication experience)

**Post-Deployment:**
13. [ ] Schedule first key rotation (90 days)
14. [ ] Document any issues encountered
15. [ ] Update runbook with lessons learned

---

## SUCCESS CRITERIA v2.0

**Security:**
- ✅ Zero OAuth tokens in URLs (verified via browser DevTools)
- ✅ Zero session keys in logs (verified via Render logs)
- ✅ JWT signed with dedicated key (not Django SECRET_KEY)
- ✅ PKCE validation 100% success rate
- ✅ CSRF protection active (POST without token returns 403)
- ✅ SameSite=Lax on all auth cookies
- ✅ No token exchange endpoint (404 on `/api/auth/exchange/`)

**Functionality:**
- ✅ Users can authenticate via Google OAuth
- ✅ Sessions persist across page refreshes
- ✅ Logout works correctly (cookies cleared)
- ✅ API requests authenticated via JWT cookie
- ✅ CSRF protection doesn't break legitimate requests

**Operations:**
- ✅ Key rotation procedure documented and tested
- ✅ Emergency rotation can be executed <1 hour
- ✅ Zero downtime during normal operations
- ✅ Monitoring alerts configured (auth failures, CSRF errors)

**Compliance:**
- ✅ OAuth 2.1 draft compliance (PKCE required)
- ✅ OWASP Top 10 addressed (A01, A02, A03, A07)
- ✅ Industry best practices followed

---

## MONITORING & ALERTS

**Metrics to Track:**
- OAuth flow success rate (target: >99%)
- PKCE validation failures (target: <0.1%)
- CSRF protection blocks (legitimate vs attacks)
- JWT validation errors (signature, expiration)
- Key rotation events

**Alert Conditions:**
- OAuth success rate drops below 95%
- PKCE validation failures >1% of requests
- JWT signature validation failures spike
- Unusual CSRF token errors (possible attack)

**Logging (Secure):**
```python
import logging

logger = logging.getLogger(__name__)

# ✅ Safe to log
logger.info(f"User {user.id} authenticated successfully")
logger.info(f"PKCE validation passed for state {state[:8]}...")

# ❌ NEVER log
# logger.info(f"Access token: {access_token}")  # ❌
# logger.info(f"Session key: {request.session.session_key}")  # ❌
# logger.info(f"PKCE verifier: {code_verifier}")  # ❌
```

---

## ROLLBACK PLAN

**If Issues Detected in Production:**

**Minor Issues (CSRF errors, cookie problems):**
1. Identify root cause in logs
2. Deploy hotfix to staging
3. Test thoroughly
4. Deploy hotfix to production

**Major Issues (Authentication broken):**
1. Revert to previous deployment (Render rollback)
2. Investigate root cause offline
3. Fix in staging
4. Full retest
5. Redeploy with fixes

**Emergency Key Rotation (Compromise):**
1. Generate new JWT_SIGNING_KEY_V2 immediately
2. Set JWT_KEY_VERSION=2
3. Set JWT_VALIDATION_KEYS=[V2 only]
4. Deploy within 1 hour
5. All users forced to re-authenticate
6. Document incident for post-mortem

---

## REFERENCES

**OAuth 2.0 & PKCE:**
- [RFC 6749: OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636: Proof Key for Code Exchange (PKCE)](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.1 Draft (PKCE required)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-09)

**CSRF Protection:**
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Django CSRF Protection Documentation](https://docs.djangoproject.com/en/4.2/ref/csrf/)

**SameSite Cookies:**
- [RFC 6265bis: SameSite Cookie Attribute](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis-09)
- [MDN: SameSite cookies explained](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)

**JWT Best Practices:**
- [RFC 7519: JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [JWT Security Best Practices](https://tools.ietf.org/html/rfc8725)

**Security Standards:**
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)

---

**END OF DOCUMENT**

*This architecture addresses all AI security review blockers and is ready for Week 2 implementation (starting December 2, 2025).*
