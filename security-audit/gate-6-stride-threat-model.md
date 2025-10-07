# Gate 6: STRIDE Threat Model - Django SSO
**Date:** October 5, 2025  
**Application:** barge2rail-auth Django SSO  
**Risk Level:** EXTREME (84/90)  
**Status:** COMPLETE ✅

---

## Executive Summary

**Total Attack Surface:** 44 endpoints across 15 public, 12 protected, 17 admin  
**Critical Vulnerabilities:** 3 (Rate limiting, AuthZ matrix, Audit logging)  
**High-Risk Issues:** 5 (OAuth validation, error messages, input validation)  
**Medium-Risk Issues:** 3 (CORS, request limits, CAPTCHA)

**Blocking Issues Before Production:**
1. 🔴 Implement rate limiting (DoS protection)
2. 🔴 Complete Gate 5 (Authorization Matrix)
3. 🔴 Complete Gate 7 (Audit Logging)

---

## Complete Endpoint Inventory

### Public Endpoints (No Authentication - 15 total)

**Health & Status:**
- `GET /health/` - Application health
- `GET /api/auth/health/` - Auth service health
- `GET /api/auth/status/` - Authentication status

**OAuth Initiation:**
- `GET /api/auth/oauth/google/url/` - Get OAuth URL
- `GET /api/auth/google/oauth-url/` - OAuth URL (alt)
- `GET /api/auth/login/google/` - Google ID token login
- `GET /api/auth/config/google/` - Config check

**OAuth Callbacks:**
- `GET /auth/google/callback/` - Main callback
- `GET /dashboard/auth/google/callback/` - Dashboard callback
- `GET /api/auth/google/callback/` - API callback

**Login UI Pages:**
- `GET /login/` - Main login page
- `GET /dashboard/login/` - Dashboard login
- `GET /dashboard/login/enhanced/` - Enhanced UI
- `GET /dashboard/login/google-test/` - Test page
- `GET /dashboard/login/google-diagnostic/` - Diagnostic
- `GET /dashboard/test/` - Simple test

### Protected Endpoints (Auth Required - 12 total)

**User Profile:**
- `GET /api/auth/me/` - Current user
- `GET /api/auth/profile/` - Profile (legacy)

**Token Management:**
- `POST /api/auth/exchange-session/` - Session → tokens
- `POST /api/auth/refresh/` - Refresh token
- `POST /api/auth/validate/` - Validate token

**Access Control:**
- `POST /api/auth/verify/` - Verify permissions

**Logout:**
- `POST /api/auth/logout/` - API logout
- `GET /dashboard/logout/` - UI logout

**Dashboard:**
- `GET /dashboard/` - Main dashboard
- `GET /dashboard/dashboard/` - Dashboard page
- `GET /dashboard/login/google-success/` - Success page

### Admin-Only Endpoints (17 total)

**Django Admin:**
- `/admin/*` - Full admin interface

**Application Management (REST):**
- `GET /api/auth/applications/` - List apps
- `POST /api/auth/applications/` - Create app
- `GET /api/auth/applications/<uuid>/` - Get app
- `PUT /api/auth/applications/<uuid>/` - Update app
- `DELETE /api/auth/applications/<uuid>/` - Delete app

**Role Management (REST):**
- `GET /api/auth/roles/` - List roles
- `POST /api/auth/roles/` - Create role
- `GET /api/auth/roles/<uuid>/` - Get role
- `PUT /api/auth/roles/<uuid>/` - Update role
- `DELETE /api/auth/roles/<uuid>/` - Delete role

---

## STRIDE Analysis

### 1. Spoofing (Identity Impersonation)

| Threat | Attack Vector | Likelihood | Impact | Mitigation | Status |
|--------|---------------|------------|--------|------------|--------|
| T1.1 | Fake OAuth tokens | Medium | Critical | Google server-side validation | ✅ Mitigated |
| T1.2 | Session hijacking | Medium | High | Secure cookies (HttpOnly, Secure, SameSite) | ✅ Mitigated |
| T1.3 | CSRF in login | Low | Medium | Django CSRF protection | ✅ Mitigated |
| T1.4 | Cookie theft (XSS) | Low | High | HttpOnly prevents JS access | ✅ Mitigated |
| T1.5 | Man-in-the-middle | Low | Critical | HTTPS + HSTS enforced | ✅ Mitigated |
| T1.6 | OAuth callback manipulation | Medium | High | Callback URL whitelist | ⚠️ VERIFY |

**Actions Required:**
- [ ] Verify OAuth redirect URIs whitelist in Google Console
- [ ] Test callback manipulation attempts
- [ ] Document accepted callback URLs

---

### 2. Tampering (Data Modification)

| Threat | Attack Vector | Likelihood | Impact | Mitigation | Status |
|--------|---------------|------------|--------|------------|--------|
| T2.1 | CSRF attacks | Medium | High | Django CSRF middleware | ✅ Mitigated |
| T2.2 | SQL injection | Low | Critical | Django ORM (parameterized) | ✅ Mitigated |
| T2.3 | Session fixation | Low | Medium | Session rotation on login | ✅ Mitigated |
| T2.4 | Parameter tampering | Medium | Medium | Input validation | ⚠️ VERIFY |
| T2.5 | Cookie tampering | Low | High | Signed cookies | ✅ Mitigated |
| T2.6 | OAuth state tampering | Medium | High | State parameter validation | ⚠️ VERIFY |

**Actions Required:**
- [ ] Verify OAuth state generation and validation
- [ ] Add input validation for all POST/PUT endpoints
- [ ] Review session security settings

---

### 3. Repudiation (Denying Actions)

| Threat | Attack Vector | Likelihood | Impact | Mitigation | Status |
|--------|---------------|------------|--------|------------|--------|
| T3.1 | No login success logs | High | Medium | Audit logging | ❌ GATE 7 |
| T3.2 | No login failure logs | High | Medium | Audit logging | ❌ GATE 7 |
| T3.3 | No admin action logs | High | High | Audit logging | ❌ GATE 7 |
| T3.4 | No user modification logs | High | High | Audit logging | ❌ GATE 7 |
| T3.5 | No permission denial logs | High | Medium | Audit logging | ❌ GATE 7 |

**BLOCKING:** Gate 7 (Comprehensive Audit Logging) is required for forensics and compliance.

---

### 4. Information Disclosure (Data Leakage)

| Threat | Attack Vector | Likelihood | Impact | Mitigation | Status |
|--------|---------------|------------|--------|------------|--------|
| T4.1 | Stack traces in prod | Low | Medium | DEBUG=False | ✅ Mitigated |
| T4.2 | Error messages leak info | Medium | Low | Generic errors | ⚠️ VERIFY |
| T4.3 | Session tokens in URLs | Low | Critical | Cookies only | ✅ Mitigated |
| T4.4 | User enumeration | Medium | Low | Generic login errors | ⚠️ VERIFY |
| T4.5 | Directory traversal | Low | High | Django static handling | ✅ Mitigated |
| T4.6 | Exposed API keys | Low | Critical | Environment variables | ✅ Mitigated |
| T4.7 | CORS misconfiguration | Medium | Medium | CORS headers | ⚠️ VERIFY |

**Actions Required:**
- [ ] Verify login errors are generic ("Invalid credentials", not "User not found")
- [ ] Review CORS_ALLOWED_ORIGINS for production
- [ ] Ensure no sensitive data in logs

---

### 5. Denial of Service (Availability)

| Threat | Attack Vector | Likelihood | Impact | Mitigation | Status |
|--------|---------------|------------|--------|------------|--------|
| T5.1 | Login brute force | High | Medium | Rate limiting | ❌ REQUIRED |
| T5.2 | OAuth callback flood | Medium | Medium | Rate limiting | ⚠️ RECOMMENDED |
| T5.3 | Resource exhaustion | Low | High | Render limits | ✅ Mitigated |
| T5.4 | Database flood | Low | High | Connection pooling | ✅ Mitigated |
| T5.5 | Large payload attacks | Low | Medium | Request size limits | ⚠️ VERIFY |

**BLOCKING:** Rate limiting on authentication endpoints is required before production.

**Recommended Implementation:**
```python
# django-axes or django-ratelimit
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=5)
AXES_LOCKOUT_PARAMETERS = ['ip_address', 'username']
```

---

### 6. Elevation of Privilege (Authorization Bypass)

| Threat | Attack Vector | Likelihood | Impact | Mitigation | Status |
|--------|---------------|------------|--------|------------|--------|
| T6.1 | Missing @login_required | Medium | Critical | Authorization Matrix | ❌ GATE 5 |
| T6.2 | Direct object reference | Medium | High | AuthZ checks | ❌ GATE 5 |
| T6.3 | Role escalation | Low | Critical | RBAC enforcement | ❌ GATE 5 |
| T6.4 | Admin bypass | Low | Critical | Django admin perms | ✅ Mitigated |

**BLOCKING:** Gate 5 (Authorization Matrix) is required to verify all endpoints have proper access controls.

---

## Risk-Ranked Mitigation Plan

### 🔴 Tier 1: BLOCKING (Must Fix Before Production)

#### M1: Rate Limiting (DoS Protection)
**Threat Addressed:** T5.1, T5.2  
**Risk:** HIGH - Brute force attacks on login  
**Implementation:**
- Install: `pip install django-axes`
- Configure: 5 attempts per IP per 5 minutes
- Endpoints: All `/api/auth/login*`, `/api/auth/register*`, OAuth callbacks
- **Effort:** 2-3 hours  
**Test:** Verify lockout after 5 failed attempts, unlock after cooldown

#### M2: Authorization Matrix (Gate 5)
**Threat Addressed:** T6.1, T6.2, T6.3  
**Risk:** CRITICAL - Privilege escalation, unauthorized access  
**Implementation:**
- Document all roles (Anon, User, Admin)
- Create permission matrix (role × endpoint)
- Write test for EVERY matrix cell (100+ tests)
- Verify default-deny behavior
- **Effort:** 6-8 hours (Claude Code)  
**Test:** Every role × endpoint × operation combination

#### M3: Comprehensive Audit Logging (Gate 7)
**Threat Addressed:** T3.1, T3.2, T3.3, T3.4, T3.5  
**Risk:** HIGH - No forensics, compliance gaps  
**Implementation:**
- Log all auth events (login, logout, failures)
- Log all admin actions
- Log all permission denials
- Structured JSON format
- Secure, immutable logs
- **Effort:** 3-4 hours (Claude Code)  
**Test:** Verify all events logged, logs are secure

---

### 🟡 Tier 2: RECOMMENDED (Fix During Canary)

#### M4: OAuth State Validation
**Threat Addressed:** T2.6  
**Risk:** MEDIUM - CSRF in OAuth flow  
**Implementation:**
- Generate random state parameter
- Store in session
- Validate on callback
- **Effort:** 1 hour

#### M5: Error Message Review
**Threat Addressed:** T4.2, T4.4  
**Risk:** LOW - Information leakage  
**Implementation:**
- Generic login errors: "Invalid credentials"
- Generic registration: "Cannot complete registration"
- No stack traces
- **Effort:** 1 hour

#### M6: Input Validation
**Threat Addressed:** T2.4  
**Risk:** MEDIUM - Data integrity  
**Implementation:**
- Django forms/serializers for all inputs
- Whitelist valid characters
- Length limits
- **Effort:** 2-3 hours

#### M7: CORS Configuration
**Threat Addressed:** T4.7  
**Risk:** MEDIUM - Cross-origin attacks  
**Implementation:**
- Set CORS_ALLOWED_ORIGINS to production domains only
- No wildcards
- **Effort:** 30 minutes

---

### 🟢 Tier 3: HARDENING (Fix Post-Launch)

- M8: Request size limits
- M9: CAPTCHA after N failures
- M10: Additional security headers (CSP, Feature-Policy)

---

## Verification Checklist

### Before Production Deployment:
- [ ] Tier 1 mitigations complete (M1, M2, M3)
- [ ] All Tier 1 mitigations tested
- [ ] Automated security scans clean
- [ ] Manual testing of attack vectors
- [ ] Documented accepted risks

### During Canary Deployment:
- [ ] Monitor for attack attempts
- [ ] Implement Tier 2 mitigations
- [ ] Test Tier 2 mitigations
- [ ] Review audit logs daily

### Post-Launch:
- [ ] Tier 3 hardening
- [ ] Regular security reviews
- [ ] Penetration testing (if budget allows)

---

## Accepted Risks

### AR1: No Professional Penetration Test
**Risk:** Unknown vulnerabilities may exist  
**Mitigation:** Comprehensive automated scanning + peer review  
**Accepted By:** [Clif]  
**Review Date:** 30 days post-deployment

### AR2: No 24/7 Security Monitoring
**Risk:** Delayed response to security incidents  
**Mitigation:** Real-time alerts + daily log review  
**Accepted By:** [Clif]  
**Review Date:** 30 days post-deployment

### AR3: Limited DDoS Protection
**Risk:** Sophisticated DDoS could overwhelm  
**Mitigation:** Render's infrastructure protection + rate limiting  
**Accepted By:** [Clif]  
**Review Date:** After 90 days, consider Cloudflare

---

## Summary

**Gate 6: STRIDE Threat Model - COMPLETE ✅**

**Critical Findings:**
- 3 blocking issues (rate limiting, authz matrix, audit logging)
- 5 recommended improvements
- 3 hardening opportunities

**Security Posture:**
- Strong foundation (HTTPS, HSTS, secure cookies)
- Critical gaps in DoS, AuthZ, and forensics
- With Tier 1 mitigations: Acceptable for internal deployment
- With Tier 2 mitigations: Good for external deployment

**Next Steps:**
1. Implement M1 (Rate Limiting)
2. Complete Gate 5 (Authorization Matrix)
3. Complete Gate 7 (Audit Logging)
4. Deploy using EXTREME RISK protocol

**Threat Model Status:** COMPLETE - Ready for implementation
