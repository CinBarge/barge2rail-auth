# Barge2Rail Authentication System Guide
## SSO + JWT + Role-Based Authorization

**Last Updated:** November 5, 2025  
**Status:** Production-Ready ✅  
**Foundation:** Django SSO at sso.barge2rail.com

---

## Table of Contents

1. [System Overview](#system-overview)
2. [How Authentication Works](#how-authentication-works)
3. [JWT Token Structure](#jwt-token-structure)
4. [Role-Based Authorization](#role-based-authorization)
5. [Adding New Applications](#adding-new-applications)
6. [User Management](#user-management)
7. [Troubleshooting](#troubleshooting)
8. [Technical Details](#technical-details)

---

## System Overview

### Architecture

```
┌─────────────────┐
│   User Browser  │
└────────┬────────┘
         │
         │ 1. Login Request
         ↓
┌─────────────────────────────────┐
│  SSO (sso.barge2rail.com)       │
│  - Django 5.x                    │
│  - django-oauth-toolkit 2.4.0   │
│  - Google Workspace OAuth        │
│  - PostgreSQL (Neon)             │
└────────┬────────────────────────┘
         │
         │ 2. JWT Token (with application_roles)
         ↓
┌──────────────────────────────────┐
│  Application (e.g., PrimeTrade)  │
│  - Validates JWT                 │
│  - Extracts application_roles     │
│  - Enforces permissions          │
└──────────────────────────────────┘
```

### Key Components

**SSO Server (sso.barge2rail.com):**
- Centralized authentication for all applications
- Issues JWT tokens with custom claims
- Manages users and application-specific roles
- Integrates with Google Workspace

**JWT Tokens:**
- Contain user identity + application roles
- Signed with RSA keys (RS256 algorithm)
- Valid for 15 minutes (configurable)
- Include refresh tokens for session management

**Application Integration:**
- Applications receive JWT tokens
- Extract `application_roles` claim
- Enforce role-based permissions
- No direct database dependency on SSO

---

## How Authentication Works

### User Login Flow

```
1. User visits application (e.g., primetrade.barge2rail.com)
   ↓
2. Application redirects to SSO with scopes: openid, email, profile, roles
   ↓
3. SSO authenticates via Google Workspace OAuth
   ↓
4. User approves access (first time only)
   ↓
5. SSO generates JWT with application_roles claim
   ↓
6. Application receives JWT token
   ↓
7. Application validates token signature
   ↓
8. Application extracts roles for this specific application
   ↓
9. User session created with appropriate permissions
```

### Technical Flow

**Step 1: Authorization Request**
```
GET https://sso.barge2rail.com/o/authorize/?
  response_type=code
  &client_id=<application_client_id>
  &redirect_uri=https://app.barge2rail.com/callback
  &scope=openid+email+profile+roles
  &state=<random_state>
```

**Step 2: Google OAuth (Internal)**
- User authenticates with Google Workspace
- SSO creates/updates user record
- User groups synced to ApplicationRole model

**Step 3: Token Exchange**
```
POST https://sso.barge2rail.com/o/token/
  grant_type=authorization_code
  &code=<authorization_code>
  &redirect_uri=https://app.barge2rail.com/callback
  &client_id=<application_client_id>
  &client_secret=<application_client_secret>
```

**Step 4: Token Response**
```json
{
  "access_token": "...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "...",
  "expires_in": 900,
  "token_type": "Bearer",
  "scope": "openid email profile roles"
}
```

---

## JWT Token Structure

### Token Claims (Decoded)

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "email": "clif@barge2rail.com",
  "email_verified": true,
  "name": "Clif Barge",
  "preferred_username": "clif@barge2rail.com",

  "application_roles": {
    "primetrade": {
      "role": "admin",
      "permissions": ["full_access"]
    },
    "database": {
      "role": "editor",
      "permissions": ["read", "write"]
    },
    "repair": {
      "role": "viewer",
      "permissions": ["read"]
    }
  },

  "is_sso_admin": true,
  "iss": "barge2rail-sso",
  "aud": "primetrade-client-id",
  "exp": 1699234567,
  "iat": 1699233667,
  "auth_time": 1699233667,
  "jti": "unique-token-id"
}
```

### Claim Descriptions

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | Unique user identifier (UUID) |
| `email` | string | User's email address |
| `email_verified` | boolean | Whether email is verified |
| `name` | string | User's full name |
| `preferred_username` | string | Username (typically email) |
| `application_roles` | object | Per-application role assignments |
| `is_sso_admin` | boolean | SSO admin privileges flag |
| `iss` | string | Token issuer (always "barge2rail-sso") |
| `aud` | string | Intended audience (application client ID) |
| `exp` | number | Expiration timestamp (Unix epoch) |
| `iat` | number | Issued at timestamp (Unix epoch) |
| `auth_time` | number | Authentication timestamp (Unix epoch) |
| `jti` | string | JWT ID (unique token identifier) |

### Scope-to-Claim Mapping

JWT claims are filtered based on requested scopes:

| Scope | Claims Included |
|-------|-----------------|
| `openid` | sub, iss, aud, exp, iat, auth_time, jti |
| `email` | email, email_verified |
| `profile` | name, preferred_username, is_sso_admin |
| `roles` | application_roles |

**Important:** Applications must request the `roles` scope to receive `application_roles` claim.

---

## Role-Based Authorization

### ApplicationRole Model

SSO manages roles using the `ApplicationRole` model:

```python
# sso/models.py
class ApplicationRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    application = models.CharField(max_length=100)  # e.g., "primetrade"
    role = models.CharField(max_length=50)  # e.g., "admin", "editor", "viewer"
    permissions = models.JSONField(default=list)  # e.g., ["read", "write", "delete"]
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['user', 'application']
```

### Role Hierarchy (Recommended)

**Admin:**
- Full access to application
- Can manage users and settings
- Permissions: `["full_access"]` or `["read", "write", "delete", "manage"]`

**Editor:**
- Can create and modify records
- Cannot manage users or settings
- Permissions: `["read", "write"]`

**Viewer:**
- Read-only access
- Can view but not modify
- Permissions: `["read"]`

### Application-Side Role Validation

Applications should validate roles like this:

```python
# Example: PrimeTrade role validation
def validate_primetrade_access(jwt_payload):
    """
    Validate user has access to PrimeTrade application.

    Args:
        jwt_payload: Decoded JWT token payload

    Returns:
        tuple: (has_access: bool, role: str, permissions: list)
    """
    # Extract application_roles claim
    app_roles = jwt_payload.get('application_roles', {})

    # Get role for this specific application
    primetrade_role = app_roles.get('primetrade')

    if not primetrade_role:
        return False, None, []

    role = primetrade_role.get('role')
    permissions = primetrade_role.get('permissions', [])

    # Validate role exists and has permissions
    if not role or not permissions:
        return False, None, []

    return True, role, permissions

# Usage in view:
def protected_view(request):
    jwt_payload = request.session.get('jwt_payload')
    has_access, role, permissions = validate_primetrade_access(jwt_payload)

    if not has_access:
        return HttpResponseForbidden("You don't have access to PrimeTrade")

    # Enforce specific permissions
    if "write" not in permissions:
        return HttpResponseForbidden("You don't have write access")

    # Proceed with authorized action
    ...
```

---

## Adding New Applications

### Prerequisites

1. Application registered in SSO (via Django admin)
2. OAuth client credentials (client_id + client_secret)
3. Redirect URIs configured

### Step-by-Step Integration

#### 1. Register Application in SSO

**Admin Panel:** https://sso.barge2rail.com/admin/oauth2_provider/application/

**Settings:**
- **Name:** Application name (e.g., "Database System")
- **Client type:** Confidential
- **Authorization grant type:** Authorization code
- **Algorithm:** RS256
- **Redirect URIs:** `https://app.barge2rail.com/auth/callback/` (one per line)
- **Scopes:** Check all needed: openid, email, profile, roles

**Save and copy:**
- Client ID: `<save this>`
- Client secret: `<save this immediately, cannot retrieve later>`

#### 2. Create ApplicationRole Records

**Django Shell or Admin Panel:**

```python
from django.contrib.auth import get_user_model
from sso.models import ApplicationRole

User = get_user_model()

# Get user
user = User.objects.get(email='clif@barge2rail.com')

# Create role for new application
ApplicationRole.objects.create(
    user=user,
    application='database',  # Application identifier (lowercase, no spaces)
    role='admin',
    permissions=['full_access']
)
```

**Bulk Creation:**

```python
# Grant all staff viewer access to new application
users = User.objects.filter(is_active=True)

for user in users:
    ApplicationRole.objects.get_or_create(
        user=user,
        application='database',
        defaults={
            'role': 'viewer',
            'permissions': ['read']
        }
    )
```

#### 3. Configure Application

**Environment Variables:**

```bash
# OAuth Configuration
SSO_URL=https://sso.barge2rail.com
SSO_CLIENT_ID=<client_id_from_step_1>
SSO_CLIENT_SECRET=<client_secret_from_step_1>
SSO_REDIRECT_URI=https://app.barge2rail.com/auth/callback/

# Scopes (space-separated)
SSO_SCOPES=openid email profile roles

# Application Identifier (must match ApplicationRole.application)
APP_IDENTIFIER=database
```

#### 4. Implement OAuth Flow

**Python/Django Example:**

```python
# views.py
from authlib.integrations.django_client import OAuth
import os

oauth = OAuth()
oauth.register(
    name='barge2rail_sso',
    client_id=os.getenv('SSO_CLIENT_ID'),
    client_secret=os.getenv('SSO_CLIENT_SECRET'),
    server_metadata_url=f"{os.getenv('SSO_URL')}/o/.well-known/openid-configuration/",
    client_kwargs={'scope': os.getenv('SSO_SCOPES')}
)

def login(request):
    """Initiate OAuth login flow."""
    redirect_uri = request.build_absolute_uri(reverse('auth_callback'))
    return oauth.barge2rail_sso.authorize_redirect(request, redirect_uri)

def callback(request):
    """Handle OAuth callback and create session."""
    # Exchange authorization code for token
    token = oauth.barge2rail_sso.authorize_access_token(request)

    # Decode JWT ID token
    id_token = token.get('id_token')
    jwt_payload = oauth.barge2rail_sso.parse_id_token(token)

    # Validate access to this application
    app_identifier = os.getenv('APP_IDENTIFIER')
    app_roles = jwt_payload.get('application_roles', {})

    if app_identifier not in app_roles:
        return HttpResponseForbidden(
            f"You don't have access to {app_identifier.title()}"
        )

    # Store JWT payload in session
    request.session['jwt_payload'] = jwt_payload
    request.session['user_email'] = jwt_payload['email']
    request.session['user_role'] = app_roles[app_identifier]['role']
    request.session['user_permissions'] = app_roles[app_identifier]['permissions']

    return redirect('dashboard')
```

#### 5. Test Integration

**Test Checklist:**

- [ ] Login redirects to SSO
- [ ] SSO shows consent screen (first time)
- [ ] User redirected back to application
- [ ] JWT token contains `application_roles.<app_identifier>`
- [ ] Application creates session successfully
- [ ] Logout clears session
- [ ] Unauthorized users see 403 error
- [ ] Role-based permissions enforced

**Test Commands:**

```bash
# 1. Test login flow in browser
open https://app.barge2rail.com/auth/login/

# 2. Capture JWT and decode
# Copy id_token from Network tab → paste at jwt.io
# Verify application_roles contains your app

# 3. Test unauthorized access
# Remove ApplicationRole record → login should fail with 403
```

---

## User Management

### Adding Users

**Via Django Admin:**

1. Navigate to https://sso.barge2rail.com/admin/
2. Auth → Users → Add user
3. Enter email and set password (temporary)
4. User will authenticate via Google Workspace on first login
5. Create ApplicationRole records for each application

**Via Django Shell:**

```python
from django.contrib.auth import get_user_model
from sso.models import ApplicationRole

User = get_user_model()

# Create user
user = User.objects.create_user(
    username='newuser@barge2rail.com',
    email='newuser@barge2rail.com',
    first_name='New',
    last_name='User'
)

# Grant access to applications
ApplicationRole.objects.create(
    user=user,
    application='primetrade',
    role='viewer',
    permissions=['read']
)

ApplicationRole.objects.create(
    user=user,
    application='database',
    role='editor',
    permissions=['read', 'write']
)
```

### Modifying Roles

**Via Django Admin:**

1. Navigate to SSO admin → Application Roles
2. Find user's role for specific application
3. Edit role and permissions
4. Save changes
5. User's next login will have updated permissions

**Via Django Shell:**

```python
from django.contrib.auth import get_user_model
from sso.models import ApplicationRole

User = get_user_model()

# Get user
user = User.objects.get(email='user@barge2rail.com')

# Update role
role = ApplicationRole.objects.get(user=user, application='primetrade')
role.role = 'admin'
role.permissions = ['full_access']
role.save()

# Or use update_or_create
ApplicationRole.objects.update_or_create(
    user=user,
    application='database',
    defaults={
        'role': 'admin',
        'permissions': ['read', 'write', 'delete']
    }
)
```

### Revoking Access

**Remove from specific application:**

```python
ApplicationRole.objects.filter(
    user=user,
    application='primetrade'
).delete()
```

**Deactivate user entirely:**

```python
user.is_active = False
user.save()
# This prevents login to ALL applications
```

---

## Troubleshooting

### Common Issues

#### Issue: "You don't have access to [Application]"

**Symptoms:** User sees 403 error after SSO login

**Causes:**
1. No ApplicationRole record exists for user + application
2. JWT doesn't contain `roles` scope
3. Application identifier mismatch

**Solutions:**

```python
# 1. Check if ApplicationRole exists
from sso.models import ApplicationRole
ApplicationRole.objects.filter(
    user__email='user@barge2rail.com',
    application='primetrade'
)

# 2. Verify scopes in OAuth application
# Admin → OAuth Applications → Check "roles" is in allowed scopes

# 3. Check application identifier matches
# SSO uses: application='primetrade'
# App expects: APP_IDENTIFIER=primetrade
```

#### Issue: JWT Token Missing application_roles Claim

**Symptoms:** JWT decoded at jwt.io shows no `application_roles` field

**Causes:**
1. Application not requesting `roles` scope
2. User has no ApplicationRole records
3. SSO code issue (rare)

**Solutions:**

```python
# 1. Verify scope request includes 'roles'
# In application OAuth config:
SSO_SCOPES=openid email profile roles  # ← Must include 'roles'

# 2. Check user has ApplicationRole records
ApplicationRole.objects.filter(user__email='user@barge2rail.com')

# 3. Check SSO logs for [CLAIMS] messages
# Render → barge2rail-auth → Logs
# Search for: [CLAIMS] get_additional_claims() called
```

#### Issue: Token Expired / Invalid Signature

**Symptoms:** Application rejects JWT with signature error

**Causes:**
1. Token expired (15 minutes default)
2. Application using wrong public key
3. Clock skew between servers

**Solutions:**

```python
# 1. Use refresh token to get new access token
# POST /o/token/ with grant_type=refresh_token

# 2. Verify application fetches public key from JWKS endpoint
# GET https://sso.barge2rail.com/o/.well-known/jwks.json

# 3. Check server times are synchronized (NTP)
```

#### Issue: Role Changes Not Reflected

**Symptoms:** User role updated in SSO but old permissions still active

**Causes:**
1. Cached JWT token (hasn't expired yet)
2. Application session not refreshed
3. Browser cached old session

**Solutions:**

```python
# 1. Force logout and re-login
# This gets fresh JWT with updated roles

# 2. Clear application session
# Logout → Clear cookies → Login again

# 3. Wait for token expiration (15 minutes)
# Or reduce token lifetime in SSO settings
```

### Debug Tools

#### Decode JWT Token

**Browser DevTools:**

```javascript
// In browser console after login:
// 1. Find token in Network tab → /o/token/ response
// 2. Copy id_token value
// 3. Go to https://jwt.io and paste
```

**Python:**

```python
import jwt
import json

token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

# Decode without verification (for debugging only)
payload = jwt.decode(token, options={"verify_signature": False})
print(json.dumps(payload, indent=2))
```

#### Check SSO Logs

**Render Dashboard:**

```bash
# Navigate to:
# Render → barge2rail-auth → Logs

# Search for:
[CLAIMS] get_additional_claims() called
[CLAIMS] User found via request.user: user@barge2rail.com
[CLAIMS] Querying ApplicationRole for user
[CLAIMS] Added role: primetrade -> admin
[CLAIMS] application_roles claim added with X apps
```

#### Verify ApplicationRole Records

**Django Shell:**

```python
from django.contrib.auth import get_user_model
from sso.models import ApplicationRole

User = get_user_model()

# List all roles for user
user = User.objects.get(email='user@barge2rail.com')
roles = ApplicationRole.objects.filter(user=user)

for role in roles:
    print(f"{role.application}: {role.role} ({role.permissions})")

# Output:
# primetrade: admin (['full_access'])
# database: editor (['read', 'write'])
```

---

## Technical Details

### Django OAuth Toolkit Configuration

**File:** `core/settings.py` (SSO project)

```python
OAUTH2_PROVIDER = {
    # Custom validator with JWT claims logic
    'OAUTH2_VALIDATOR_CLASS': 'sso.oauth_validators.CustomOAuth2Validator',

    # OIDC Configuration
    'OIDC_ENABLED': True,
    'OIDC_RSA_PRIVATE_KEY': os.getenv('OIDC_RSA_PRIVATE_KEY'),

    # Token lifetimes
    'ACCESS_TOKEN_EXPIRE_SECONDS': 900,  # 15 minutes
    'AUTHORIZATION_CODE_EXPIRE_SECONDS': 60,
    'REFRESH_TOKEN_EXPIRE_SECONDS': 1209600,  # 14 days

    # Scopes
    'SCOPES': {
        'read': 'Read access',
        'write': 'Write access',
        'openid': 'OpenID Connect',
        'profile': 'User profile information',
        'email': 'User email address',
        'roles': 'Application roles and permissions',
    },

    # Other settings
    'REQUEST_APPROVAL_PROMPT': 'auto',
}
```

### Custom OAuth Validator

**File:** `sso/oauth_validators.py`

The `CustomOAuth2Validator` class extends django-oauth-toolkit with custom JWT claims:

```python
class CustomOAuth2Validator(OAuth2Validator):
    """Custom validator for django-oauth-toolkit 2.4.0"""

    # Scope-to-claim mapping for security
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope.copy()
    oidc_claim_scope.update({
        "application_roles": "roles",
        "email": "email",
        "name": "profile",
        "is_sso_admin": "profile",
    })

    def get_additional_claims(self, request):
        """
        Add custom claims to JWT ID token.
        Called by django-oauth-toolkit during token generation.
        """
        # Implementation injects application_roles from ApplicationRole model
        # See source code for full implementation
```

### Public Key (JWKS) Endpoint

Applications should fetch the public key from:

```
GET https://sso.barge2rail.com/o/.well-known/jwks.json
```

**Response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "unique-key-id",
      "alg": "RS256",
      "n": "public-key-modulus...",
      "e": "AQAB"
    }
  ]
}
```

### OpenID Configuration

Discovery endpoint:

```
GET https://sso.barge2rail.com/o/.well-known/openid-configuration/
```

### Security Considerations

**Token Security:**
- JWT signed with RS256 (RSA + SHA-256)
- Private key stored in environment variable (never committed)
- Public key available via JWKS endpoint
- Tokens expire after 15 minutes

**Transport Security:**
- All connections via HTTPS (enforced by Render)
- Client secrets never exposed to browser
- Authorization codes single-use, expire in 60 seconds

**Session Security:**
- Refresh tokens valid for 14 days
- Refresh tokens can be revoked
- User logout revokes all tokens

---

## Recent Changes

### November 2025: JWT Claims Enhancement

**Change:** Enhanced `get_additional_claims()` method in `CustomOAuth2Validator`

**Impact:**
- JWT tokens now reliably include `application_roles` claim
- Admin bypass no longer needed for PrimeTrade
- Scope mapping added for security compliance
- Improved defensive coding for user access paths

**Migration:**
- No database changes required
- Existing sessions continue to work
- New logins get enhanced JWT tokens
- Zero downtime deployment

**Reference:** See `AUTHENTICATION_FIX_NOV_2025.md` for technical details

---

## Support

**For Authentication Issues:**
1. Check this guide's Troubleshooting section
2. Review SSO logs in Render dashboard
3. Verify ApplicationRole records in Django admin
4. Test JWT token structure at jwt.io

**For New Application Integration:**
1. Follow "Adding New Applications" section
2. Test each step in order
3. Use test credentials first
4. Monitor SSO logs during testing

**For Role Changes:**
1. Update ApplicationRole in Django admin
2. User must logout and re-login for changes to take effect
3. Or wait for token expiration (15 minutes)

---

**Last Updated:** November 5, 2025  
**Maintained By:** Barge2Rail Infrastructure Team  
**System Status:** Production-Ready ✅
