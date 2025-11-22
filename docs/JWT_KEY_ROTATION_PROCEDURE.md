# JWT Key Rotation Procedure
**System:** barge2rail-auth (Django SSO)  
**Version:** 1.0  
**Created:** November 21, 2025  
**Purpose:** Step-by-step guide for rotating JWT signing keys safely

---

## OVERVIEW

**Why Rotate JWT Keys:**
- Security best practice (NIST recommends every 90 days)
- Compliance requirements
- Employee offboarding
- Suspected key compromise
- Proactive security posture

**Rotation Strategy:** Overlap rotation (zero downtime)
- Week 1: Old key only (V1)
- Week 2: Both keys valid (V1 + V2), new JWTs use V2
- Week 3: New key only (V2), old key removed

**Key Points:**
- ✅ No user disruption (zero downtime)
- ✅ Gradual migration (1 week overlap)
- ✅ Rollback possible if issues
- ✅ Emergency rotation <1 hour if needed

---

## NORMAL ROTATION (Every 90 Days)

### Timeline: 2 Weeks Total

```
Week 1: Preparation
- Generate new key (V2)
- Add to staging environment
- Test overlap validation
- Monitor for issues

Week 2: Production Deployment
- Deploy V2 to production
- Switch active key to V2
- Monitor JWT validation success
- Deprecate V1 after 7 days
```

---

## STEP-BY-STEP: NORMAL ROTATION

### Week 1: Preparation Phase

**Step 1: Generate New JWT Signing Key (5 minutes)**

```bash
# SSH into server or run locally with Django environment
python manage.py generate_jwt_key

# Output example:
# Generated JWT signing key:
# xK9mP3vR8nL2qW5eT7yU4hA1dF6gS0jC9bV3nM8xZ2

# Copy this key - you'll need it for environment variables
```

**What this does:**
- Generates cryptographically secure 256-bit key (32 bytes)
- Uses `secrets.token_urlsafe()` for randomness
- Base64 URL-safe encoding

**Save securely:**
- Password manager (1Password, LastPass, etc.)
- Encrypted notes (offline backup)
- **NEVER commit to git or Slack**

---

**Step 2: Add New Key to Staging Environment (10 minutes)**

**Render Dashboard:**
1. Navigate to: https://dashboard.render.com/web/srv-d479pummcj7s73d89qq0
2. Click "Environment" tab
3. Add new environment variable:
   - Key: `JWT_SIGNING_KEY_V2`
   - Value: `[paste generated key from Step 1]`
4. Keep existing `JWT_SIGNING_KEY_V1` unchanged
5. Keep `JWT_KEY_VERSION=1` (not switching yet)
6. Click "Save Changes"
7. Service will auto-redeploy (takes ~2-3 minutes)

**Environment State After Step 2:**
```bash
JWT_SIGNING_KEY_V1=<old-key>       # Still active for signing
JWT_SIGNING_KEY_V2=<new-key>       # Only for validation (not signing yet)
JWT_KEY_VERSION=1                  # V1 is active
```

---

**Step 3: Test Overlap Validation in Staging (15 minutes)**

**Test A: Old JWTs Still Work**
```bash
# In browser DevTools or Postman

# 1. Get existing JWT (issued with V1)
# Look in browser cookies or:
curl https://staging-sso.barge2rail.com/api/auth/status/ \
  -H "Cookie: jwt_token=<existing-jwt>"

# Expected: 200 OK (V1 JWT validates successfully)
```

**Test B: New JWTs Use V1 (Not Switched Yet)**
```bash
# 1. Log out
# 2. Log in via Google OAuth
# 3. Decode JWT to check key_version claim

# In browser console:
const jwt = document.cookie.match(/jwt_token=([^;]+)/)[1];
const payload = JSON.parse(atob(jwt.split('.')[1]));
console.log('Key version:', payload.key_version);

# Expected: key_version = 1 (still using V1 for signing)
```

**Test C: Overlap Window Working**
```python
# Optional: Manual validation test in Django shell
from django.conf import settings
import jwt

# Decode with V2 key (should work for new JWTs eventually)
decoded = jwt.decode(
    token,
    settings.JWT_SIGNING_KEY_V2,
    algorithms=['HS256']
)
print(decoded)
```

**Success Criteria:**
- ✅ Existing users stay logged in
- ✅ New logins work
- ✅ No JWT validation errors in logs
- ✅ Both keys present in settings

---

**Step 4: Monitor Staging for 3-7 Days**

**What to Watch:**
- Authentication success rate (should stay >99%)
- JWT validation errors (should be near zero)
- User complaints (should be zero)

**Where to Monitor:**
- Render logs: https://dashboard.render.com/web/srv-d479pummcj7s73d89qq0/logs
- Application metrics (if configured)
- User feedback

**If Issues Found:**
- Revert by removing `JWT_SIGNING_KEY_V2`
- Investigate root cause
- Fix and retry Step 2-3

**If No Issues:**
- Proceed to Week 2 (production deployment)

---

### Week 2: Production Switch Phase

**Step 5: Deploy V2 Key to Production (10 minutes)**

**Render Dashboard (Production):**
1. Navigate to: https://dashboard.render.com/web/srv-[production-id]
2. Click "Environment" tab
3. Add new environment variable:
   - Key: `JWT_SIGNING_KEY_V2`
   - Value: `[paste same key from Step 1]`
4. Keep `JWT_SIGNING_KEY_V1` unchanged
5. Keep `JWT_KEY_VERSION=1` (not switching yet)
6. Click "Save Changes"
7. Production redeploys (~2-3 minutes)

**Environment State After Step 5:**
```bash
# Production
JWT_SIGNING_KEY_V1=<old-key>       # Still active
JWT_SIGNING_KEY_V2=<new-key>       # Available for validation
JWT_KEY_VERSION=1                  # V1 still active
```

**Critical:** Do NOT change `JWT_KEY_VERSION` yet. This step just makes V2 available for validation.

---

**Step 6: Switch Active Key to V2 (5 minutes)**

**Wait 1 Hour After Step 5**
- Allows production to stabilize
- Confirms no immediate issues
- Gives time to monitor logs

**Render Dashboard (Production):**
1. Click "Environment" tab
2. Find `JWT_KEY_VERSION`
3. Change value from `1` to `2`
4. Click "Save Changes"
5. Production redeploys (~2-3 minutes)

**Environment State After Step 6:**
```bash
JWT_SIGNING_KEY_V1=<old-key>       # Validation only
JWT_SIGNING_KEY_V2=<new-key>       # NOW ACTIVE for signing + validation
JWT_KEY_VERSION=2                  # V2 is active
```

**What Changed:**
- ✅ New logins get JWTs signed with V2
- ✅ Old JWTs (signed with V1) still validate
- ✅ Users stay logged in (no disruption)

---

**Step 7: Monitor for 7 Days (Gradual Migration)**

**Why 7 Days:**
- JWT expiration: 1 hour (but refresh tokens extend sessions)
- Users who don't return for days need overlap period
- Safety margin for unexpected edge cases

**Monitoring Dashboard (Daily):**

| Metric | Target | Action if Below |
|--------|--------|-----------------|
| Auth success rate | >99% | Investigate logs |
| JWT validation success | >99.9% | Check key configuration |
| V1 JWT usage | Decreasing daily | Normal - users migrating |
| V2 JWT usage | Increasing daily | Normal - new logins |

**How to Check JWT Version Distribution:**

```python
# Django shell or management command
from apps.auth.models import User
from django.core.cache import cache

# Count active sessions by key version
v1_count = 0
v2_count = 0

for user in User.objects.filter(is_active=True):
    token_version = cache.get(f'jwt_version_{user.id}')
    if token_version == 1:
        v1_count += 1
    elif token_version == 2:
        v2_count += 1

print(f'V1 JWTs: {v1_count}')
print(f'V2 JWTs: {v2_count}')
print(f'Migration: {v2_count / (v1_count + v2_count) * 100:.1f}%')

# Expected: V2 percentage increases daily
# After 7 days: Should be >95% V2
```

---

**Step 8: Deprecate V1 Key (5 minutes)**

**When to Execute:**
- ✅ 7 days passed since Step 6
- ✅ >95% of JWTs using V2 (Step 7 monitoring)
- ✅ No JWT validation errors in logs
- ✅ No user complaints

**Render Dashboard (Production):**
1. Click "Environment" tab
2. **DELETE** `JWT_SIGNING_KEY_V1` environment variable
3. Click "Save Changes"
4. Production redeploys (~2-3 minutes)

**Environment State After Step 8:**
```bash
JWT_SIGNING_KEY_V2=<new-key>       # Only key (signing + validation)
JWT_KEY_VERSION=2                  # V2 active
# JWT_SIGNING_KEY_V1 removed
```

**What Changed:**
- ✅ Only V2 key remains
- ✅ Old JWTs (V1) now invalid
- ⚠️ Users with V1 JWTs forced to re-authenticate (should be <5%)

---

**Step 9: Update Documentation (5 minutes)**

**Update Key Rotation Log:**
```bash
# Create or append to: ROTATION_LOG.md

## Rotation 2025-11-21
**Type:** Normal (90-day rotation)
**Old Key:** V1 (created 2025-08-20)
**New Key:** V2 (created 2025-11-21)
**Started:** 2025-11-21
**V2 Activated:** 2025-11-28
**V1 Deprecated:** 2025-12-05
**Status:** Complete ✅

**Issues:** None
**User Impact:** Zero disruption
**Next Rotation:** 2026-02-20 (90 days)
```

**Update Password Manager:**
- Mark old key (V1) as "Deprecated 2025-12-05"
- Mark new key (V2) as "Active 2025-12-05"
- Set calendar reminder for next rotation (90 days)

---

**Step 10: Schedule Next Rotation (2 minutes)**

**Calendar Event:**
- Date: 90 days from today (February 20, 2026)
- Title: "JWT Key Rotation Due"
- Description: "Follow JWT_KEY_ROTATION_PROCEDURE.md"
- Reminder: 1 week before (February 13, 2026)

---

## EMERGENCY ROTATION (Key Compromise)

**Scenarios Requiring Emergency Rotation:**
- Key accidentally committed to public git repo
- Key discovered in logs or error messages
- Employee with key access terminated
- Security audit finds key exposure
- Breach notification from third party

**Timeline: 1 Hour Total**

---

## STEP-BY-STEP: EMERGENCY ROTATION

### Phase 1: Immediate Action (15 minutes)

**Step 1: Generate Emergency Key (2 minutes)**

```bash
python manage.py generate_jwt_key

# Save immediately to password manager
# Example: kL8pW2vN5xR9mQ3eT6yH7uA0dC4fG1jS8bZ2nV5xM
```

---

**Step 2: Deploy Emergency Key to Production (5 minutes)**

**Render Dashboard (Production):**
1. Navigate to environment variables
2. **UPDATE** `JWT_SIGNING_KEY_V2` with new emergency key
3. **DELETE** `JWT_SIGNING_KEY_V1` (compromised)
4. **SET** `JWT_KEY_VERSION=2`
5. Click "Save Changes" (immediate redeploy)

**Environment State After Step 2:**
```bash
JWT_SIGNING_KEY_V2=<emergency-key>  # NEW emergency key
JWT_KEY_VERSION=2                   # V2 active
# JWT_SIGNING_KEY_V1 DELETED (compromised)
```

---

**Step 3: Force All Users to Re-Authenticate (5 minutes)**

**Option A: Invalidate All Sessions (Recommended)**
```python
# Django shell
from django.contrib.sessions.models import Session
Session.objects.all().delete()

# Result: All users logged out immediately
```

**Option B: Invalidate JWTs Only**
```python
# Update JWT key version in database
from apps.auth.models import User
User.objects.update(jwt_version_valid=2)

# Middleware rejects JWTs with jwt_version < 2
```

**Option C: Both (Maximum Security)**
```bash
# Execute both Option A and Option B
```

---

**Step 4: Notify Users (3 minutes)**

**Email Template:**
```
Subject: Security Update - Please Log In Again

Hi [Name],

We've completed a security update to our authentication system.
You'll need to log in again using Google OAuth.

This is a routine security measure and your data is safe.

Questions? Contact support@barge2rail.com

Thanks,
barge2rail.com Team
```

**Send via:**
- SendGrid bulk email
- In-app notification banner
- Dashboard alert

---

### Phase 2: Verification (30 minutes)

**Step 5: Verify All Old JWTs Invalid (10 minutes)**

```bash
# Test with old JWT (should fail)
curl https://sso.barge2rail.com/api/auth/status/ \
  -H "Cookie: jwt_token=<old-jwt>"

# Expected: 401 Unauthorized (JWT signature invalid)
```

**Step 6: Test New Authentication Flow (10 minutes)**

```bash
# Full OAuth flow:
# 1. Log out completely
# 2. Click "Login with Google"
# 3. Approve permissions
# 4. Verify redirect to dashboard
# 5. Verify API calls work
# 6. Decode JWT - should show key_version=2
```

**Step 7: Monitor Logs for Issues (10 minutes)**

**Watch For:**
- Authentication failures (should be zero after re-login)
- JWT signature errors (should be zero)
- User complaints (address immediately)

**Render Logs:**
```bash
# Filter for errors
grep "JWT" /var/log/application.log | grep "ERROR"

# Expected: No errors after users re-authenticate
```

---

### Phase 3: Documentation (15 minutes)

**Step 8: Incident Report (10 minutes)**

```markdown
## Emergency Key Rotation - 2025-11-21

**Trigger:** [Key committed to public repo / Log exposure / etc.]
**Detected:** 2025-11-21 14:30 UTC
**Rotation Started:** 2025-11-21 14:45 UTC
**Rotation Complete:** 2025-11-21 15:30 UTC

**Actions Taken:**
1. Generated emergency key
2. Deployed to production (removed compromised key)
3. Invalidated all sessions
4. Notified users via email
5. Verified new authentication flow

**User Impact:**
- All users forced to re-authenticate
- ~10 users logged in at time of rotation
- Zero data loss
- ~45 minutes total disruption

**Root Cause:**
[Detailed explanation of how key was compromised]

**Preventive Measures:**
[How we'll prevent this in future]

**Status:** Resolved ✅
```

**Step 9: Update Security Documentation (5 minutes)**

- Update password manager (mark old key as "COMPROMISED - DO NOT USE")
- Update key rotation log
- Schedule next rotation (90 days)
- Brief team on incident (if applicable)

---

## TROUBLESHOOTING

### Issue: Users Can't Log In After Rotation

**Symptoms:**
- Authentication redirects loop
- "Invalid JWT" errors
- Users stuck on login page

**Diagnosis:**
```bash
# Check environment variables
echo $JWT_SIGNING_KEY_V1
echo $JWT_SIGNING_KEY_V2
echo $JWT_KEY_VERSION

# Check which key is being used for signing
python manage.py shell
>>> from django.conf import settings
>>> print(f"Active key: {settings.JWT_SIGNING_KEY[:10]}...")
>>> print(f"Version: {settings.JWT_KEY_VERSION}")
```

**Fix:**
1. Verify `JWT_KEY_VERSION` matches intended active key
2. Verify key value is correct (no extra spaces, newlines)
3. Restart application (Render auto-restart on env change)
4. Test with fresh OAuth flow

---

### Issue: Old JWTs Not Validating During Overlap

**Symptoms:**
- Users logged out unexpectedly during overlap period
- "JWT signature invalid" errors
- Validation errors in logs

**Diagnosis:**
```python
# Check if both keys present in validation list
from django.conf import settings
print(f"Validation keys: {len(settings.JWT_VALIDATION_KEYS)}")
# Expected: 2 during overlap period

# Test manual validation with both keys
import jwt
for key in settings.JWT_VALIDATION_KEYS:
    try:
        decoded = jwt.decode(old_jwt, key, algorithms=['HS256'])
        print(f"Valid with key: {key[:10]}...")
        break
    except jwt.InvalidSignatureError:
        continue
```

**Fix:**
1. Verify both `JWT_SIGNING_KEY_V1` and `JWT_SIGNING_KEY_V2` set
2. Verify `settings.JWT_VALIDATION_KEYS` includes both
3. Check for typos in key values
4. Redeploy if keys not loaded correctly

---

### Issue: High Rate of Re-Authentication After V1 Deprecation

**Symptoms:**
- >5% of users forced to re-authenticate after Step 8
- User complaints about being logged out

**Diagnosis:**
```python
# Check JWT version distribution before deprecation
# (Should run this BEFORE Step 8)
from apps.auth.models import User

v1_active = User.objects.filter(jwt_version=1, last_login__gte=timezone.now()-timedelta(days=1)).count()
v2_active = User.objects.filter(jwt_version=2, last_login__gte=timezone.now()-timedelta(days=1)).count()

print(f"V1: {v1_active} ({v1_active/(v1_active+v2_active)*100:.1f}%)")
print(f"V2: {v2_active} ({v2_active/(v1_active+v2_active)*100:.1f}%)")

# If V1 > 5%, wait longer before deprecating
```

**Prevention:**
- Wait full 7 days after Step 6 before Step 8
- Monitor migration progress daily
- Only deprecate V1 when <5% users on old key

**Remediation:**
- Send proactive email: "You may need to log in again"
- Add banner: "Session expired, please log in"
- No data loss, just inconvenience

---

## CHECKLIST SUMMARY

### Normal Rotation Checklist

**Preparation (Week 1):**
- [ ] Generate new key with `python manage.py generate_jwt_key`
- [ ] Save key securely in password manager
- [ ] Add `JWT_SIGNING_KEY_V2` to staging
- [ ] Test overlap validation (old JWTs still work)
- [ ] Monitor staging for 3-7 days
- [ ] No errors in logs

**Production Switch (Week 2):**
- [ ] Add `JWT_SIGNING_KEY_V2` to production
- [ ] Wait 1 hour, monitor logs
- [ ] Change `JWT_KEY_VERSION` to `2`
- [ ] Monitor for 7 days (gradual migration)
- [ ] Verify >95% users on V2
- [ ] Delete `JWT_SIGNING_KEY_V1`
- [ ] Update documentation (rotation log)
- [ ] Schedule next rotation (90 days)

---

### Emergency Rotation Checklist

**Immediate (15 minutes):**
- [ ] Generate emergency key
- [ ] Deploy to production (update V2, delete V1)
- [ ] Set `JWT_KEY_VERSION=2`
- [ ] Invalidate all sessions
- [ ] Notify users via email

**Verification (30 minutes):**
- [ ] Test old JWTs invalid
- [ ] Test new authentication flow works
- [ ] Monitor logs for errors
- [ ] Address user complaints

**Documentation (15 minutes):**
- [ ] Write incident report
- [ ] Update security documentation
- [ ] Brief team (if applicable)
- [ ] Schedule next rotation

---

## TOOLS & COMMANDS REFERENCE

### Generate New Key
```bash
python manage.py generate_jwt_key
```

### Check Current Configuration
```python
# Django shell
from django.conf import settings

print(f"Active version: {settings.JWT_KEY_VERSION}")
print(f"Active key: {settings.JWT_SIGNING_KEY[:10]}...")
print(f"Validation keys: {len(settings.JWT_VALIDATION_KEYS)}")
```

### Decode JWT (Debug)
```python
import jwt

# Decode without verification (debug only)
decoded = jwt.decode(token, options={"verify_signature": False})
print(f"Key version: {decoded.get('key_version')}")
print(f"Issued at: {decoded.get('iat')}")
print(f"Expires: {decoded.get('exp')}")
```

### Invalidate All Sessions
```python
# Django shell
from django.contrib.sessions.models import Session
Session.objects.all().delete()
```

### Monitor JWT Version Distribution
```python
# Custom management command or Django shell
from apps.auth.models import User
from datetime import timedelta
from django.utils import timezone

active_users = User.objects.filter(
    last_login__gte=timezone.now() - timedelta(days=1)
)

v1_count = active_users.filter(jwt_version=1).count()
v2_count = active_users.filter(jwt_version=2).count()

print(f"Active in last 24h: {active_users.count()}")
print(f"V1: {v1_count} ({v1_count/active_users.count()*100:.1f}%)")
print(f"V2: {v2_count} ({v2_count/active_users.count()*100:.1f}%)")
```

---

## FREQUENTLY ASKED QUESTIONS

**Q: How often should we rotate JWT keys?**
A: Normal rotation every 90 days. Emergency rotation immediately upon compromise.

**Q: Will users be logged out during rotation?**
A: No. Normal rotation has 7-day overlap - users stay logged in. Emergency rotation forces re-authentication.

**Q: What if we need to roll back?**
A: During overlap period (Week 2): Change `JWT_KEY_VERSION` back to `1`. After V1 deprecated: Restore V1 from password manager, deploy, switch version.

**Q: Can we skip the 7-day overlap?**
A: Not recommended. Overlap prevents user disruption. For small user base (<10 users), could reduce to 3 days minimum.

**Q: What if key is compromised but we're unsure?**
A: Rotate immediately (emergency procedure). Better safe than sorry. User disruption < data breach.

**Q: How do we test rotation in staging first?**
A: Follow Steps 1-4 in staging environment. Test for 3-7 days. Then execute Steps 5-10 in production.

---

**END OF PROCEDURE**

*Keep this document updated after each rotation with lessons learned and process improvements.*
