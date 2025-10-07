# Django SSO Security Implementation - Claude Code Handoff
**Date:** October 5, 2025  
**Project:** barge2rail-auth Django SSO  
**Working Directory:** `/Users/cerion/Projects/barge2rail-auth`  
**Risk Level:** EXTREME (84/90)  
**Estimated Time:** 11-15 hours

---

## Mission

Implement three BLOCKING security requirements to make Django SSO production-ready:
1. **M1: Rate Limiting** (DoS protection) - 2-3 hours
2. **Gate 5: Authorization Matrix** (Complete access control) - 6-8 hours  
3. **Gate 7: Audit Logging** (Forensics capability) - 3-4 hours

---

## Current Status

### ✅ Completed (Gates 0-4, 6)
- **Gate 0:** Secrets Management - PASS
- **Gate 1:** Dependency Security - PASS (0 vulnerabilities!)
- **Gate 2:** Code Security - PASS (0 HIGH severity issues)
- **Gate 3:** Configuration - PASS (Excellent HSTS)
- **Gate 4:** Access Control Baseline - PARTIAL (framework present)
- **Gate 6:** STRIDE Threat Model - COMPLETE (comprehensive analysis)

**Security Assessment Location:** `/Users/cerion/Projects/barge2rail-auth/security-audit/`

### ❌ Your Mission (Gates 5, 7 + M1)
Three blocking issues prevent production deployment. Your job: implement all three.

---

## Context: Where We Are

### Strong Foundation ✅
- Zero known vulnerabilities
- Clean, secure code
- Excellent HTTPS configuration
- Proper secrets management

### Critical Gaps 🔴
1. **No rate limiting** → Brute force attacks succeed
2. **Incomplete authorization** → Regular users can access admin endpoints
3. **No audit logging** → Blind to security incidents

### Your Impact
After your work: **System goes from Grade B- to Grade A-** (production-ready)

---

## Implementation Priority Order

**Start with the easiest, build momentum:**

### Phase 1: Rate Limiting (M1) - START HERE
- **Why first:** Simplest implementation (2-3 hours)
- **Impact:** Immediate DoS protection
- **Quick win:** Builds confidence

### Phase 2: Audit Logging (Gate 7) - SECOND
- **Why second:** Medium complexity (3-4 hours)
- **Impact:** Foundation for monitoring
- **Needed for:** Gate 5 testing and verification

### Phase 3: Authorization Matrix (Gate 5) - FINAL
- **Why last:** Most complex (6-8 hours)
- **Impact:** Complete access control
- **Depends on:** Audit logging for verification

---

## Phase 1: Rate Limiting Implementation

### Objective
Prevent brute force attacks on authentication endpoints.

### Detailed Spec Location
See artifact: "Gate 6: STRIDE Threat Model" → Section M1: Rate Limiting

### Implementation Steps

#### 1. Install django-axes
```bash
cd /Users/cerion/Projects/barge2rail-auth
source .venv/bin/activate
pip install django-axes
pip freeze > requirements.txt
```

#### 2. Configure in core/settings.py
```python
# Add to INSTALLED_APPS
INSTALLED_APPS = [
    # ... existing apps ...
    'axes',  # Add this
]

# Add to MIDDLEWARE (AFTER AuthenticationMiddleware)
MIDDLEWARE = [
    # ... existing middleware ...
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'axes.middleware.AxesMiddleware',  # Add this line
    # ... rest of middleware ...
]

# Add axes configuration
from datetime import timedelta

AXES_FAILURE_LIMIT = 5  # Lock after 5 failed attempts
AXES_COOLOFF_TIME = timedelta(minutes=5)  # 5 minute lockout
AXES_LOCKOUT_PARAMETERS = ['ip_address', 'username']  # Track both
AXES_RESET_ON_SUCCESS = True  # Reset counter on successful login
AXES_VERBOSE = True  # Log lockouts
```

#### 3. Run Migrations
```bash
python manage.py migrate axes
```

#### 4. Test Rate Limiting
```bash
# Manual test: Try logging in with wrong password 6 times
# 6th attempt should return 403 with lockout message

# Verify lockout expires after 5 minutes
```

### Success Criteria
- [ ] django-axes installed and in requirements.txt
- [ ] Middleware configured correctly (after AuthenticationMiddleware)
- [ ] Settings configured (5 attempts, 5 min cooloff)
- [ ] Migrations run successfully
- [ ] Manual testing shows lockout after 5 failures
- [ ] Successful login resets counter
- [ ] Lockout expires after 5 minutes

### Estimated Time: 2-3 hours

---

## Phase 2: Audit Logging Implementation

### Objective
Log all security-relevant events for forensics and compliance.

### Detailed Spec Location
See artifact: "Gate 7: Audit Logging - Implementation Spec"

### Implementation Summary

#### 1. Configure Django Logging (core/settings.py)
Add comprehensive logging configuration with:
- JSON formatter for structured logs
- Separate audit log file
- Security log file
- Log rotation (10MB, 50 backups)

#### 2. Create Audit Utility (sso/audit.py)
Create utility module with functions:
- `log_authentication_event()` - Login/logout/OAuth
- `log_authorization_event()` - Permission checks
- `log_data_event()` - Data modifications
- `log_security_event()` - Security incidents

#### 3. Add Logging to Views
Update these files:
- `sso/views.py` - Add audit logging to all endpoints
- `sso/auth_views.py` - Add OAuth event logging
- `dashboard/views.py` - Add dashboard event logging

Log these events:
- Login success/failure
- OAuth callbacks (success/failure)
- Logout
- Token refresh
- Permission denied (403 responses)
- Admin actions (create/update/delete)

#### 4. Create Tests (sso/tests/test_audit_logging.py)
Verify:
- Login success is logged
- Login failure is logged
- Logout is logged
- Permission denials are logged
- Log format is JSON
- Sensitive data is redacted

#### 5. Log Rotation & Monitoring
Create management commands:
- `sso/management/commands/rotate_audit_logs.py`
- `sso/management/commands/check_security_logs.py`

### Success Criteria
- [ ] Django logging configured in settings.py
- [ ] python-json-logger installed
- [ ] sso/audit.py created with all utility functions
- [ ] All authentication events logged
- [ ] All authorization failures logged
- [ ] All admin actions logged
- [ ] Logs in JSON format
- [ ] Sensitive data redacted (passwords, secrets)
- [ ] Tests exist and pass
- [ ] Log rotation configured

### Estimated Time: 3-4 hours

**Full detailed spec in artifact: "Gate 7: Audit Logging - Implementation Spec"**

---

## Phase 3: Authorization Matrix Implementation

### Objective
Create comprehensive test coverage for all role × endpoint combinations.

### Detailed Spec Location
See artifact: "Gate 5: Authorization Matrix - Implementation Spec"

### Implementation Summary

#### 1. Define Roles (sso/roles.py)
```python
class UserRole:
    ANONYMOUS = 'anonymous'
    USER = 'user'
    ADMIN = 'admin'
```

#### 2. Create Authorization Matrix Document
Create: `docs/AUTHORIZATION_MATRIX.md`
- List all 44 endpoints
- Map roles to permissions (Read, Write, Delete)
- Document expected behavior

#### 3. Create Test Infrastructure
Create: `sso/tests/test_authorization.py`

Test classes:
- `PublicEndpointTests` - 15 endpoints × 3 roles = 45 tests
- `ProtectedEndpointTests` - 12 endpoints × 3 roles = 36 tests
- `AdminEndpointTests` - 11 endpoints × 3 roles × CRUD = 132+ tests
- `DefaultDenyTests` - Verify default behavior
- `ErrorMessageTests` - Verify safe error messages

**Minimum: 100+ tests total**

#### 4. Fix Admin Permissions
Update views to use `IsAdminUser` instead of `IsAuthenticated`:
```python
# In sso/views.py
from rest_framework.permissions import IsAdminUser

class ApplicationListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAdminUser]  # Change from IsAuthenticated

# Same for all Application and Role views
```

#### 5. Run and Fix Tests
```bash
python manage.py test sso.tests.test_authorization
```

Fix any failing tests by:
- Adding missing decorators
- Correcting permission classes
- Ensuring 403 (not 404) for denied requests

### Success Criteria
- [ ] sso/roles.py created
- [ ] docs/AUTHORIZATION_MATRIX.md complete (all 44 endpoints)
- [ ] sso/tests/test_authorization.py created
- [ ] 100+ authorization tests exist
- [ ] All tests pass (100% pass rate)
- [ ] Denied requests return 403
- [ ] Admin endpoints require admin permissions
- [ ] Default-deny behavior verified

### Estimated Time: 6-8 hours

**Full detailed spec in artifact: "Gate 5: Authorization Matrix - Implementation Spec"**

---

## After All Phases Complete

### Run Full Security Gate Suite
```bash
cd /Users/cerion/Projects/barge2rail-auth
source .venv/bin/activate

# Gate 0: Secrets
git secrets --scan-history

# Gate 1: Dependencies  
safety check

# Gate 2: Code security
bandit -r sso dashboard core -x .venv,venv -f json

# Gate 3: Configuration
python manage.py check --deploy

# Gate 5: Authorization (NEW)
python manage.py test sso.tests.test_authorization

# Gate 7: Audit logging (NEW)
python manage.py test sso.tests.test_audit_logging

# All tests
python manage.py test
```

**Expected:** All gates pass, all tests pass

---

## Integration Testing

### Test 1: Rate Limiting
```bash
# Should succeed
curl -X POST http://localhost:8000/api/auth/login/ \
  -d "email=test@test.com&password=correctpass"

# Should fail 5 times, then block on 6th
for i in {1..6}; do
  curl -X POST http://localhost:8000/api/auth/login/ \
    -d "email=test@test.com&password=wrongpass"
  echo "\nAttempt $i"
done
```

### Test 2: Authorization Matrix
Test that:
- Anonymous cannot access protected endpoints (403)
- Users can access user endpoints (200)
- Users cannot access admin endpoints (403)
- Admins can access admin endpoints (200)

### Test 3: Audit Logging
```bash
# Check logs exist and are JSON
cat logs/audit.log | jq .

# Verify events are logged
grep "login.success" logs/audit.log | jq .
grep "permission_denied" logs/audit.log | jq .
```

---

## Deliverables

### Files to Create
1. `sso/roles.py` - Role definitions
2. `docs/AUTHORIZATION_MATRIX.md` - Complete matrix
3. `sso/audit.py` - Audit logging utility
4. `sso/tests/test_authorization.py` - AuthZ tests (100+)
5. `sso/tests/test_audit_logging.py` - Logging tests
6. `sso/management/commands/rotate_audit_logs.py`
7. `sso/management/commands/check_security_logs.py`

### Files to Modify
1. `core/settings.py` - Add axes + logging config
2. `sso/views.py` - Add audit logging + fix permissions
3. `sso/auth_views.py` - Add audit logging
4. `dashboard/views.py` - Add audit logging
5. `requirements.txt` - Add django-axes, python-json-logger

---

## Quality Standards

### Code Quality
- [ ] No `print()` statements (use logging)
- [ ] No hardcoded credentials
- [ ] No TODO comments unresolved
- [ ] Consistent code style
- [ ] All functions have docstrings
- [ ] Clean git commits

### Testing Standards
- [ ] All tests have descriptive names
- [ ] All tests have docstrings
- [ ] Tests are independent
- [ ] No test data pollution
- [ ] Clear assertions

---

## Common Issues & Solutions

### Issue: Tests failing because views don't exist
**Solution:** Skip with `@unittest.skip`, note in matrix

### Issue: OAuth callbacks hard to test
**Solution:** Mock Google OAuth responses

### Issue: Can't determine correct behavior
**Solution:** Follow principle of least privilege (default DENY)

### Issue: Audit logs filling disk
**Solution:** Ensure rotation configured, test it works

---

## Success Definition

### Phase 1 Complete When:
✅ Rate limiting blocks after 5 attempts  
✅ Lockout expires after 5 minutes  
✅ Successful login resets counter

### Phase 2 Complete When:
✅ All auth events logged  
✅ All authz failures logged  
✅ All admin actions logged  
✅ Logs in JSON format  
✅ Sensitive data redacted

### Phase 3 Complete When:
✅ 100+ authorization tests exist  
✅ All tests pass  
✅ Admin endpoints require admin perms  
✅ Denied requests return 403

### ALL PHASES Complete When:
✅ All security gates (0-7) pass  
✅ Integration tests pass  
✅ Quality standards met  
✅ Ready for production deployment

---

## Timeline

**Optimistic:** 11 hours (smooth implementation)  
**Realistic:** 13-15 hours (with debugging)  
**Conservative:** 17 hours (with challenges)

**Recommended approach:** Work in focused 2-3 hour blocks

---

## After Completion

### Report Back With:
1. ✅ Status of each phase (Complete/Blocked/Partial)
2. ✅ Test results (X tests, Y passed, Z failed)
3. ✅ Any blockers or questions
4. ✅ Time spent (actual vs estimated)
5. ✅ Git diff summary of changes

### Then:
**The Bridge will:**
1. Review your work
2. Run independent verification
3. Create deployment plan
4. Coordinate production deployment

---

## Reference Documents

**In security-audit directory:**
- `SECURITY_ASSESSMENT_SUMMARY.md` - Overall status
- `gate-6-stride-threat-model.md` - Complete threat analysis
- All other gate documents (0-4)

**Artifacts in previous conversation:**
- "Gate 5: Authorization Matrix - Implementation Spec"
- "Gate 7: Audit Logging - Implementation Spec"
- "Claude Code Handoff Document" (has even more detail)

---

## The Bottom Line

**You have everything you need:**
- ✅ Clear specifications
- ✅ Detailed examples
- ✅ Success criteria
- ✅ Testing procedures
- ✅ Full context

**This is BLOCKING work for EXTREME RISK deployment.**

- Quality over speed
- Test thoroughly
- Document issues
- Ask if unclear

**You can do this. Let's make Django SSO production-ready! 🚀**

---

## Quick Start Checklist

Before you begin:
- [ ] Read this entire document
- [ ] Review security assessment summary
- [ ] Check that venv is activated
- [ ] Confirm working directory is correct
- [ ] Review detailed specs for each phase

Then:
- [ ] Phase 1: Rate Limiting (2-3 hrs)
- [ ] Phase 2: Audit Logging (3-4 hrs)
- [ ] Phase 3: Authorization Matrix (6-8 hrs)
- [ ] Integration testing
- [ ] Report results

**Let's go!**
