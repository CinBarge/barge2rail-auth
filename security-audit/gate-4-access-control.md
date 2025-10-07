# Gate 4: Access Control Baseline
**Date:** October 5, 2025  
**Project:** Django SSO (barge2rail-auth)  
**Risk Level:** EXTREME (84/90)  
**Status:** ⚠️ PARTIAL PASS (Gate 5 required for complete verification)

---

## Objective
Verify that protected endpoints have proper authentication and authorization controls in place.

---

## Execution

### Decorator Scan
```bash
cd /Users/cerion/Projects/barge2rail-auth
grep -rn '@login_required|@staff_member_required|@permission_required' sso/ dashboard/
grep -rn 'permission_classes|IsAuthenticated|IsAdminUser' sso/
```

### Code Review
Manual review of view files to verify access control implementation.

---

## Findings Summary

### ✅ Access Control Framework Present
- Django's `@login_required` decorator used for function-based views
- DRF's `permission_classes` used for API views
- `AllowAny` explicitly declared for public endpoints
- `IsAuthenticated` used for protected endpoints

---

## Access Control Inventory

### Dashboard Views (Function-Based)
**File:** `dashboard/views.py`

| View | Line | Protection | Status |
|------|------|------------|--------|
| `dashboard()` | 76 | `@login_required` | ✅ PROTECTED |
| `logout_view()` | 83 | `@login_required` | ✅ PROTECTED |
| Other views | Various | No decorator | ⚠️ **NEEDS REVIEW** |

**Note:** Other dashboard views appear to be login pages (public), but this needs verification in Gate 5.

---

### API Views (Permission Classes)

#### Public Endpoints (AllowAny) - 14 identified
**File:** `sso/views.py` and `sso/auth_views.py`

These endpoints are **intentionally public** (OAuth flow, health checks, etc.):
- Health/status endpoints
- OAuth initiation and callbacks
- Login/registration endpoints

**Status:** ✅ **CORRECT** - These should be public

---

#### Protected Endpoints (IsAuthenticated) - 6+ identified

| Endpoint Type | View | Protection | Status |
|---------------|------|------------|--------|
| User Profile | Function views | `IsAuthenticated` | ✅ PROTECTED |
| Applications (List/Create) | `ApplicationListCreateView` | `IsAuthenticated` | ✅ PROTECTED |
| Applications (Detail) | `ApplicationDetailView` | `IsAuthenticated` | ✅ PROTECTED |
| Roles (List/Create) | `UserRoleListCreateView` | `IsAuthenticated` | ✅ PROTECTED |
| Roles (Detail) | `UserRoleDetailView` | `IsAuthenticated` | ✅ PROTECTED |

---

## Access Control Patterns

### ✅ Function-Based Views (Decorators)
```python
from django.contrib.auth.decorators import login_required

@login_required
def dashboard(request):
    # Only authenticated users can access
```

### ✅ API Views (Permission Classes)
```python
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    # Only authenticated users can access
```

### ✅ Class-Based API Views
```python
from rest_framework.permissions import IsAuthenticated

class ApplicationListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]
    # Only authenticated users can list/create applications
```

---

## Issues Identified

### ⚠️ Issue 1: No Admin-Level Permissions
**Problem:** Application and Role endpoints use `IsAuthenticated` instead of admin-only permissions

**Current:**
```python
class ApplicationListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]  # Any logged-in user
```

**Should be:**
```python
from rest_framework.permissions import IsAdminUser

class ApplicationListCreateView(generics.ListCreateAPIView):
    permission_classes = [IsAdminUser]  # Only admins/superusers
```

**Impact:** **HIGH** - Regular users can create/modify applications and roles  
**Status:** ❌ **MUST FIX** (Gate 5 will address this)

---

### ⚠️ Issue 2: Incomplete Coverage Verification
**Problem:** Cannot verify all endpoints are properly protected without comprehensive testing

**What we know:**
- ✅ Key protected endpoints have controls
- ✅ Public endpoints explicitly marked `AllowAny`
- ⚠️ Unknown if ALL endpoints are covered

**Status:** ⚠️ **REQUIRES GATE 5** (Authorization Matrix + Testing)

---

## Critical Gap: Authorization Matrix Missing

### What Gate 4 Confirms
✅ **Authentication controls exist** (login_required, IsAuthenticated)

### What Gate 4 CANNOT Confirm
❌ **Authorization controls** (who can do what)
❌ **Complete endpoint coverage** (are all endpoints protected?)
❌ **Permission boundaries** (user vs admin access)

**This is why Gate 5 (Authorization Matrix) is BLOCKING for EXTREME RISK deployment.**

---

## Recommendations

### BLOCKING: Gate 5 Required
1. **Create complete authorization matrix** mapping:
   - All endpoints
   - All roles (Anonymous, User, Admin)
   - All permissions (Read, Write, Delete)

2. **Add admin-level permissions:**
   ```python
   # Applications and Roles should be admin-only
   permission_classes = [IsAdminUser]  # NOT IsAuthenticated
   ```

3. **Test every permission combination:**
   - Anonymous access (should be denied except public endpoints)
   - User access (limited permissions)
   - Admin access (full permissions)

---

## Compliance

**OWASP A01:2021 - Broken Access Control:** ⚠️ Partially addressed, needs Gate 5  
**CWE-284 - Improper Access Control:** ⚠️ Framework present, testing required  
**CWE-285 - Improper Authorization:** ❌ Admin permissions missing

---

## Verification Checklist

### Gate 4 (Baseline) - Completed
- [x] Authentication framework present
- [x] `@login_required` used for function views
- [x] `permission_classes` used for API views
- [x] Public endpoints explicitly marked
- [x] Protected endpoints have authentication

### Gate 5 (Complete) - Required
- [ ] Authorization matrix created
- [ ] All endpoints documented
- [ ] Admin permissions implemented
- [ ] Every role × endpoint tested
- [ ] Default-deny behavior verified
- [ ] Denied operations return 403 (not 404/500)

---

## Sign-Off

**Executed by:** Clif + The Bridge  
**Date:** October 5, 2025  
**Status:** ⚠️ PARTIAL PASS - Gate 5 REQUIRED for complete verification  
**Next Gate:** Gate 5 - Authorization Matrix (BLOCKING)

---

## Notes

Gate 4 confirms that authentication controls are present and the framework for access control exists. However, **Gate 4 alone is insufficient for EXTREME RISK deployment**.

**Critical findings:**
1. ✅ Authentication framework is solid
2. ❌ Authorization granularity missing (no admin-only controls on sensitive endpoints)
3. ⚠️ Complete coverage cannot be verified without Gate 5 testing

**Gate 5 (Authorization Matrix) is MANDATORY** to:
- Verify ALL endpoints are protected
- Implement proper authorization (not just authentication)
- Test every permission combination
- Ensure admin endpoints require admin permissions

**Access Control Grade: C+** (Framework present, implementation incomplete)
