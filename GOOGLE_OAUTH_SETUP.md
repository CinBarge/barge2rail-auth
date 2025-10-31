# Google OAuth Setup Guide

**Last Updated:** October 28, 2025
**For:** barge2rail-auth SSO System

---

## Critical Configuration

### Redirect URI (MUST MATCH EXACTLY)

The OAuth redirect URI is **automatically constructed** from your `BASE_URL`:

```
{BASE_URL}/auth/google/callback/
```

**Production:**
```
https://sso.barge2rail.com/auth/google/callback/
```

**Development:**
```
http://127.0.0.1:8000/auth/google/callback/
```

**IMPORTANT:**
- The trailing slash `/` is **REQUIRED**
- URIs are **case-sensitive**
- Protocol (`http` vs `https`) must match exactly
- Any mismatch will cause `redirect_uri_mismatch` errors

---

## Google Cloud Console Configuration

### Step 1: Create OAuth 2.0 Client ID

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to: **APIs & Services** → **Credentials**
3. Click **Create Credentials** → **OAuth client ID**
4. Application type: **Web application**
5. Name: `Barge2Rail SSO` (or your preferred name)

### Step 2: Configure Authorized Origins

Add these **Authorized JavaScript origins:**

**Production:**
```
https://sso.barge2rail.com
```

**Development (local testing):**
```
http://127.0.0.1:8000
http://localhost:8000
```

### Step 3: Configure Redirect URIs

Add these **Authorized redirect URIs:**

**Production:**
```
https://sso.barge2rail.com/auth/google/callback/
```

**Development (local testing):**
```
http://127.0.0.1:8000/auth/google/callback/
http://localhost:8000/auth/google/callback/
```

**CRITICAL:** Include the trailing slash `/` in all redirect URIs!

### Step 4: Save and Copy Credentials

1. Click **Create**
2. Copy the **Client ID** and **Client Secret**
3. Add to your `.env` file:
   ```bash
   GOOGLE_CLIENT_ID=your-client-id-here.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-client-secret-here
   ```

---

## Environment Configuration

### Production (.env on Render)

```bash
# Django
SECRET_KEY=your-production-secret-key-at-least-50-characters
DEBUG=False
ALLOWED_HOSTS=sso.barge2rail.com
BASE_URL=https://sso.barge2rail.com

# Google OAuth
GOOGLE_CLIENT_ID=your-production-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-production-client-secret

# CSRF
CSRF_TRUSTED_ORIGINS=https://sso.barge2rail.com

# Database (Render provides this automatically)
DATABASE_URL=postgresql://...
```

### Development (.env locally)

```bash
# Django
SECRET_KEY=your-dev-secret-key-at-least-50-characters
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1
BASE_URL=http://127.0.0.1:8000

# Google OAuth
GOOGLE_CLIENT_ID=your-dev-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-dev-client-secret

# CSRF
CSRF_TRUSTED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
```

---

## Testing the Configuration

### 1. Check Configuration Endpoint

```bash
curl http://127.0.0.1:8000/api/auth/debug/google/
```

Expected response should show:
- `client_id_from_decouple`: Your client ID
- `google_auth_available`: `true`
- `current_origin`: Your BASE_URL

### 2. Test OAuth Flow

1. Navigate to: `http://127.0.0.1:8000/auth/login/google/`
2. Should redirect to Google consent screen
3. After approving, should redirect back to `/auth/google/callback/`
4. Should complete authentication successfully

---

## Troubleshooting

### Error: `redirect_uri_mismatch`

**Cause:** The redirect URI sent to Google doesn't match what's configured in Google Console

**Solution:**
1. Check your `BASE_URL` in `.env`
2. Verify redirect URI in Google Console: `{BASE_URL}/auth/google/callback/`
3. Ensure trailing slash is present
4. Ensure protocol matches (`http` vs `https`)
5. Restart Django server after changing `.env`

**Check what Django is sending:**
```python
# In Django shell
from django.conf import settings
print(f"{settings.BASE_URL}/auth/google/callback/")
```

### Error: `invalid_client`

**Cause:** Client ID or Client Secret is incorrect

**Solution:**
1. Verify `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`
2. Ensure no extra whitespace or quotes
3. Verify credentials in Google Console match exactly

### Error: `access_denied`

**Cause:** User clicked "Cancel" on Google consent screen

**Solution:** This is expected user behavior, no configuration issue

---

## Multiple Environments

If you need separate OAuth clients for development and production:

1. **Create TWO OAuth clients in Google Console:**
   - `Barge2Rail SSO (Production)` - with production redirect URI
   - `Barge2Rail SSO (Development)` - with development redirect URIs

2. **Use different credentials:**
   - Production `.env`: Production Client ID/Secret
   - Development `.env`: Development Client ID/Secret

3. **Benefits:**
   - Separate audit logs
   - Independent configuration
   - No accidental production auth in development

---

## Security Checklist

- [ ] Client Secret is in `.env` (NOT in code)
- [ ] `.env` is in `.gitignore`
- [ ] Production uses HTTPS (not HTTP)
- [ ] Redirect URI includes trailing slash
- [ ] CSRF_TRUSTED_ORIGINS matches BASE_URL
- [ ] ALLOWED_HOSTS matches BASE_URL domain
- [ ] Google Console restricts to authorized origins
- [ ] Only authorized users can access admin

---

## Reference

**Official Documentation:**
- [Google OAuth 2.0 Setup](https://developers.google.com/identity/protocols/oauth2)
- [Django OAuth Toolkit](https://django-oauth-toolkit.readthedocs.io/)

**Internal Documentation:**
- `CLAUDE.md` - Django SSO conventions
- `TECHNICAL_DEBT.md` - OAuth implementation notes
- `.env.example` - Configuration template
