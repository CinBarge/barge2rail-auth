# CORS Fix - Production Deployment Instructions

## 🚨 URGENT: Frontend "Failed to fetch" Error Resolution

**Issue Confirmed:** The OAuth backend API is working perfectly, but CORS (Cross-Origin Resource Sharing) configuration is blocking frontend browser requests from https://sso.barge2rail.com.

**Error:** `TypeError: Failed to fetch` in frontend JavaScript when calling `/api/auth/google/oauth-url/`

## Root Cause Analysis ✅

### ✅ Backend API Status
- **Working:** `https://sso.barge2rail.com/api/auth/oauth/google/url/`
- **Returns:** Valid Google OAuth authorization URLs
- **Status:** API endpoints fully functional

### ❌ CORS Configuration Issue  
- **Missing:** `https://sso.barge2rail.com` in `CORS_ALLOWED_ORIGINS`
- **Current:** Only localhost origins allowed
- **Impact:** Browser blocks all cross-origin API requests

## Required Changes for Production

### 1. **Update Django Settings** (`core/settings.py`)

**Current CORS Configuration:**
```python
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000',
).split(',')
```

**Fixed CORS Configuration:**
```python
# CORS - Allow both development and production origins
CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000,https://sso.barge2rail.com',
).split(',')
CORS_ALLOW_CREDENTIALS = True

# Additional CORS settings for production
CORS_ALLOW_ALL_ORIGINS = config('CORS_ALLOW_ALL_ORIGINS', default=False, cast=bool)
CORS_ALLOWED_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]
```

### 2. **Update Render Configuration** (`render.yaml`)

**Add environment variable:**
```yaml
      - key: CORS_ALLOWED_ORIGINS
        value: "https://sso.barge2rail.com,http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000"
```

## Deployment Options

### Option 1: Git Push (Recommended)
```bash
# Commit and push changes to trigger automatic Render deployment
git add core/settings.py render.yaml
git commit -m "Fix CORS configuration for production domain"
git push origin main
```

### Option 2: Manual Environment Variable (Quick Fix)
If git push isn't available, manually add this environment variable in Render dashboard:
- **Key:** `CORS_ALLOWED_ORIGINS`  
- **Value:** `https://sso.barge2rail.com,http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000`

### Option 3: Direct File Edit
Edit `core/settings.py` directly on the server to include the production domain.

## Validation After Deployment

### 1. **Test CORS Headers**
```bash
# Should return Access-Control-Allow-Origin header
curl -v -H "Origin: https://sso.barge2rail.com" \
     "https://sso.barge2rail.com/api/auth/oauth/google/url/"
```

### 2. **Test Preflight Request**
```bash
# Should handle OPTIONS request properly
curl -v -X OPTIONS \
     -H "Origin: https://sso.barge2rail.com" \
     -H "Access-Control-Request-Method: GET" \
     "https://sso.barge2rail.com/api/auth/oauth/google/url/"
```

### 3. **Run Validation Script**
```bash
./test_cors_fix.sh
```

## Expected Results After Deployment

### ✅ CORS Headers Present
```
Access-Control-Allow-Origin: https://sso.barge2rail.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Headers: accept, authorization, content-type, origin, user-agent, x-csrftoken, x-requested-with
```

### ✅ Frontend JavaScript Working
- No more `TypeError: Failed to fetch` errors
- OAuth URL requests successful
- Complete OAuth authentication flow functional

### ✅ Browser Network Tab
- API requests show successful CORS preflight (OPTIONS 200)
- API responses include proper CORS headers
- No console errors related to CORS

## Current Status

### ✅ Local Changes Ready
- [x] CORS configuration updated in `core/settings.py`
- [x] Render configuration updated in `render.yaml`  
- [x] Validation script created (`test_cors_fix.sh`)
- [x] Changes committed to local git repository

### ⏳ Deployment Pending
- [ ] Push changes to GitHub repository
- [ ] Render automatic deployment triggered
- [ ] Production CORS headers validated
- [ ] Frontend OAuth flow confirmed working

## Business Impact After Fix

### ✅ Immediate Resolution
- OAuth authentication flow fully functional
- Users can sign in with Google Workspace accounts
- Frontend JavaScript API calls successful

### ✅ System Integration Ready
- SSO foundation complete for business applications
- PrimeTrade integration can proceed
- Google Sheets consolidation strategy enabled

---

## Summary

**The fix is simple but critical:** Add `https://sso.barge2rail.com` to the CORS allowed origins list and deploy to production. This will immediately resolve the "Failed to fetch" errors and enable complete OAuth functionality.

**Deployment Priority:** HIGH - Blocks all frontend OAuth functionality until deployed.
