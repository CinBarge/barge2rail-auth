# JWT Signature Verification Deployment Plan

## Overview
This deployment enables cryptographic verification of JWT tokens between SSO and PrimeTrade, closing a critical security gap where tokens were previously accepted without signature validation.

## Security Impact
**BEFORE:** JWT tokens decoded with `verify_signature: False` - any forged token accepted
**AFTER:** JWT signatures cryptographically verified - only tokens signed by SSO accepted

## Changes Summary

### SSO Repository (barge2rail-auth)
1. **New dependency:** PyJWKClient==0.9.0
2. **New endpoint:** `/.well-known/jwks.json` - Public key distribution
3. **New file:** `sso/jwks_views.py` - JWKS endpoint implementation
4. **Updated:** `sso/urls.py` - Added JWKS route
5. **Tests:** `sso/tests/test_jwks.py` - JWKS endpoint verification

### PrimeTrade Repository (django-primetrade)
1. **Dependency updates:**
   - Django: 4.2 → 5.2.8 (align with SSO)
   - PyJWT: >=2.8.0 → 2.10.1 (pin exact version)
   - PyJWKClient: 0.9.0 (new)
   - gunicorn: 21.2.0 → 23.0.0 (align with SSO)
   - cryptography: >=41.0.0 → 46.0.3 (align with SSO)
   - Other minor version bumps for consistency

2. **Security enhancement:** `primetrade_project/auth_views.py`
   - Enabled JWT signature verification
   - Added JWKS public key fetching
   - Comprehensive error handling for JWT failures
   - Validates: signature, expiration, audience, issuer

3. **Tests:** `primetrade_project/test_jwt_verification.py` - Security test suite

## Deployment Sequence

### CRITICAL: Deploy in this exact order to avoid breaking production

### Phase 1: Deploy SSO (Non-Breaking)
**Goal:** Add JWKS endpoint while PrimeTrade still uses old verification

```bash
# 1. SSH into barge2rail-auth repository
cd /path/to/barge2rail-auth

# 2. Create feature branch
git checkout -b feat/jwt-signature-verification

# 3. Commit changes
git add requirements.txt sso/jwks_views.py sso/urls.py sso/tests/test_jwks.py
git commit -m "feat: add JWKS endpoint for JWT signature verification

- Add PyJWKClient dependency
- Implement /.well-known/jwks.json endpoint
- Expose RSA public key for token verification
- Add comprehensive JWKS tests

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# 4. Push and deploy
git push origin feat/jwt-signature-verification
```

**Verify SSO deployment:**
```bash
# Test JWKS endpoint is accessible
curl https://sso.barge2rail.com/api/auth/.well-known/jwks.json

# Expected: JSON with "keys" array containing RSA public key
# Should see: {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", ...}]}
```

**At this point:**
- ✅ SSO has JWKS endpoint live
- ✅ PrimeTrade still works (uses old verification)
- ✅ No user-facing changes

### Phase 2: Test PrimeTrade Changes Locally
**Goal:** Verify JWT verification works against production SSO

```bash
# 1. In django-primetrade repository
cd /path/to/django-primetrade

# 2. Update dependencies locally
pip install -r requirements.txt

# 3. Run tests
python manage.py test primetrade_project.test_jwt_verification

# 4. Test against production SSO
# Set environment variables:
export SSO_BASE_URL=https://sso.barge2rail.com
export SSO_CLIENT_ID=<your-client-id>
export SSO_CLIENT_SECRET=<your-secret>
export SSO_REDIRECT_URI=http://localhost:8000/auth/callback/

# 5. Start local server
python manage.py runserver

# 6. Test authentication flow manually
# - Visit http://localhost:8000/auth/login/
# - Complete SSO flow
# - Verify successful login
# - Check logs for "JWT verified and decoded successfully"
```

**Verification checklist:**
- [ ] JWKS endpoint fetched successfully
- [ ] JWT signature verified
- [ ] User logged in successfully
- [ ] No 403 errors from signature validation
- [ ] Logs show `[FLOW DEBUG 5.4] Retrieved signing key`

### Phase 3: Deploy PrimeTrade (Breaking Change)
**Goal:** Enable signature verification in production

```bash
# 1. Create feature branch
git checkout -b feat/enable-jwt-verification

# 2. Commit changes
git add requirements.txt primetrade_project/auth_views.py primetrade_project/test_jwt_verification.py
git commit -m "feat: enable JWT signature verification

- Update dependencies to match SSO versions
- Enable JWT signature verification via JWKS
- Add comprehensive error handling
- Validate signature, expiration, audience, issuer
- Add security test suite

BREAKING: Forged tokens now rejected

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# 3. Push and deploy
git push origin feat/enable-jwt-verification
```

**Monitor deployment:**
```bash
# Watch Render logs during deployment
# Look for any JWT verification errors

# Expected successful auth flow logs:
# - [FLOW DEBUG 5.3] Fetching JWKS from: https://sso.barge2rail.com/api/auth/.well-known/jwks.json
# - [FLOW DEBUG 5.4] Retrieved signing key: barge2rail-sso-2025
# - [FLOW DEBUG 6] JWT verified and decoded successfully

# ERROR patterns to watch for:
# - "JWT SIGNATURE INVALID" (indicates forged token or key mismatch)
# - "JWT EXPIRED" (normal, user needs to re-auth)
# - "JWKS unavailable" (SSO endpoint unreachable)
```

### Phase 4: Verify Production
**Goal:** Confirm security fix is working

**Test with valid user:**
1. Visit https://prt.barge2rail.com/auth/login/
2. Complete SSO authentication
3. Verify successful login
4. Check Render logs for signature verification

**Test with forged token (security validation):**
1. Attempt to manually create JWT with modified role
2. Submit to PrimeTrade
3. **Expected:** 403 Forbidden with "Invalid token signature"
4. **Success criteria:** Forged token rejected

**Verification checklist:**
- [ ] Normal users can log in successfully
- [ ] Forged tokens are rejected (403 error)
- [ ] Logs show signature verification happening
- [ ] No increase in authentication failures
- [ ] Session behavior unchanged

## Rollback Plan

### If Phase 3 fails (PrimeTrade deployment issues):

**Option 1: Rollback PrimeTrade deployment**
```bash
# In Render dashboard:
# 1. Go to django-primetrade service
# 2. Manual Deploy → Select previous commit
# 3. Deploy

# Expected recovery time: 5-10 minutes
```

**Option 2: Emergency fix (if rollback fails)**
```python
# In primetrade_project/auth_views.py, line 265:
# Temporarily disable signature verification:
decoded = jwt.decode(id_token, options={"verify_signature": False})

# Push emergency fix:
git commit -am "fix: temporarily disable JWT verification (emergency)"
git push
```

### If Phase 1 fails (SSO deployment issues):

**Rollback SSO:**
```bash
# SSO changes are non-breaking - rollback only if JWKS endpoint fails
# In Render dashboard: rollback barge2rail-sso service
```

**Impact:** PrimeTrade unaffected (doesn't use JWKS yet)

## Testing Checklist

### Pre-Deployment Tests

**SSO Tests:**
```bash
cd barge2rail-auth
python manage.py test sso.tests.test_jwks
```

**PrimeTrade Tests:**
```bash
cd django-primetrade
python manage.py test primetrade_project.test_jwt_verification
```

### Post-Deployment Tests

**Functional Tests:**
1. [ ] User can log in via SSO
2. [ ] User can log out
3. [ ] User roles are preserved
4. [ ] Session persists correctly
5. [ ] Logs show signature verification

**Security Tests:**
1. [ ] Forged token rejected (modify payload, sign with wrong key)
2. [ ] Expired token rejected (set exp in past)
3. [ ] Wrong audience rejected (change aud claim)
4. [ ] Wrong issuer rejected (change iss claim)

**Integration Tests:**
1. [ ] SSO → PrimeTrade auth flow works
2. [ ] Multiple users can authenticate
3. [ ] Role-based redirects work
4. [ ] No increase in error rates

## Environment Variables

**No new environment variables required.**

Existing configuration sufficient:
- `OIDC_RSA_PRIVATE_KEY` (SSO) - Already set
- `SSO_BASE_URL` (PrimeTrade) - Already set
- `SSO_CLIENT_ID` (PrimeTrade) - Already set

## Dependencies

**SSO:**
- PyJWKClient==0.9.0 (new)

**PrimeTrade:**
- Django: 4.2 → 5.2.8
- PyJWT: >=2.8.0 → 2.10.1
- PyJWKClient: 0.9.0 (new)
- gunicorn: 21.2.0 → 23.0.0
- cryptography: >=41.0.0 → 46.0.3

## Success Criteria

**Security:**
- ✅ JWT signature verification enabled
- ✅ Forged tokens rejected (InvalidSignatureError)
- ✅ Only SSO-signed tokens accepted
- ✅ Audience/issuer validation enforced

**Functionality:**
- ✅ All existing auth flows work
- ✅ User login/logout functional
- ✅ Role assignments work
- ✅ No user-facing disruption

**Testing:**
- ✅ JWKS endpoint tests pass
- ✅ JWT verification tests pass
- ✅ Integration tests pass
- ✅ Security validation tests pass

## Timeline Estimate

- **Phase 1 (SSO):** 15 minutes deploy + 10 minutes verification = 25 minutes
- **Phase 2 (Local test):** 30 minutes testing
- **Phase 3 (PrimeTrade):** 15 minutes deploy + 20 minutes verification = 35 minutes
- **Phase 4 (Production verify):** 30 minutes

**Total estimated time:** 2 hours

**Best deployment window:** Low-traffic period (evening/weekend)

## Support & Troubleshooting

### Common Issues

**Issue: "JWKS unavailable"**
- **Cause:** SSO JWKS endpoint unreachable
- **Fix:** Verify https://sso.barge2rail.com/api/auth/.well-known/jwks.json accessible
- **Check:** SSO deployment status, network connectivity

**Issue: "Invalid token signature"**
- **Cause:** Key mismatch between SSO signing and PrimeTrade verification
- **Fix:** Verify OIDC_RSA_PRIVATE_KEY configured in SSO
- **Check:** JWKS endpoint returns valid public key

**Issue: "Authentication service temporarily unavailable"**
- **Cause:** Network timeout fetching JWKS
- **Fix:** Check network connectivity, SSO service health
- **Workaround:** Temporary rollback if persistent

**Issue: Increased 403 errors after deployment**
- **Cause:** Possible token expiration or caching issues
- **Fix:** Users need to re-authenticate (clear sessions)
- **Expected:** Short spike in 403s as old tokens expire

### Monitoring

**Key metrics to watch:**
- Authentication success rate (should remain constant)
- 403 error rate (expect small spike, then stabilize)
- Average login time (should be <5% slower due to JWKS fetch)
- JWKS endpoint response time (should be <100ms)

**Log patterns:**
```
# Success:
"JWT verified and decoded successfully"
"Retrieved signing key: barge2rail-sso-2025"

# Failure (investigate):
"JWT SIGNATURE INVALID"
"JWKS unavailable"
"Authentication failed"
```

## Questions & Answers

**Q: Will existing user sessions be affected?**
A: No. This affects new logins only. Existing sessions continue working.

**Q: What happens if JWKS endpoint is down?**
A: New logins will fail with 403. Existing sessions unaffected. SSO health endpoint should be monitored.

**Q: Can we deploy SSO and PrimeTrade simultaneously?**
A: Not recommended. SSO first ensures JWKS available before PrimeTrade starts using it.

**Q: How long are JWKS keys cached?**
A: PyJWKClient default: 360 seconds (6 minutes). Keys automatically refreshed.

**Q: What happens during SSO key rotation?**
A: PyJWKClient fetches new key automatically. Brief period where both keys valid.

## References

- PyJWT Documentation: https://pyjwt.readthedocs.io/
- JWKS Specification: RFC 7517
- Current insecure code: primetrade_project/auth_views.py:255
- SSO signing code: sso/tokens.py
- Technical analysis: [Analysis report from previous conversation]

---

**Deployment Status:** Not yet deployed
**Last Updated:** 2025-11-07
**Author:** Claude Code
**Reviewer:** Pending (The Bridge CTO review required)
