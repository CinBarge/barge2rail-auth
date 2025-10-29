# Technical Debt: OAuth Implementation Duplication

**Discovered:** October 28, 2025 during bug fix (redirect_uri mismatch)
**Risk:** MEDIUM (code duplication, maintenance burden)
**Recommendation:** Consolidate three OAuth implementations into one canonical version

---

## Current State

**Three Separate Google OAuth Implementations:**

1. **`sso/views.py:1095`** - `google_auth_callback`
   - Redirect URI: `/auth/google/callback/`
   - Routed at: `/auth/google/callback/` (direct route in core/urls.py)
   - Purpose: Main callback handler

2. **`sso/auth_views.py:56 & 326`** - `login_google` + `google_auth_callback`
   - Redirect URI: `/auth/google/callback/`
   - Routed at: `/auth/login/google/` and `/auth/google/callback/` (via include)
   - Purpose: User authentication flow

3. **`sso/oauth_views.py:56 & 328`** - `login_google` + `google_auth_callback`
   - Redirect URI: ~~`/api/auth/google/callback/`~~ **FIXED to `/auth/google/callback/`** (Oct 28, 2025)
   - Routed at: `/api/auth/login/google/` and `/api/auth/google/callback/` (via include)
   - Purpose: API-based authentication flow

**URL Routing Conflicts in `core/urls.py`:**
```python
Line 18: path("auth/google/callback/", google_auth_callback, ...)  # Direct route (sso.views)
Line 22: path("api/auth/", include("sso.urls"))                     # Includes oauth_views
Line 23: path("auth/", include("sso.urls"))                         # Includes auth_views - OVERLAP!
```

---

## Issues

1. **Code Duplication:** Three nearly-identical OAuth implementations
2. **Maintenance Burden:** Bug fixes must be applied to all three implementations
3. **Routing Confusion:** Overlapping URL patterns make it unclear which implementation handles requests
4. **Inconsistent Error Handling:** Each implementation may handle errors differently
5. **Testing Complexity:** Must test all three OAuth paths

---

## Immediate Fix Applied (October 28, 2025)

**Problem:** `oauth_views.py` used different redirect URI (`/api/auth/google/callback/`) causing Google OAuth `redirect_uri_mismatch` errors.

**Solution:** Standardized all implementations on `/auth/google/callback/`

**Files Changed:**
- `sso/oauth_views.py` - Lines 96 and 376

**Risk Level of Fix:** LOW (configuration change only, no logic changes)

---

## Recommended Future Action

**Goal:** Consolidate into single canonical OAuth implementation

**Approach:**
1. **Phase 1: Analysis** (30 minutes)
   - Identify which implementation is most complete and well-tested
   - Map all current usages and dependencies
   - Document differences between implementations

2. **Phase 2: Consolidation** (1-2 hours)
   - Choose canonical implementation (likely `sso/views.py`)
   - Migrate all OAuth logic to single module
   - Update URL routing to eliminate overlaps
   - Add comprehensive docstrings explaining OAuth flow

3. **Phase 3: Deprecation** (30 minutes)
   - Remove duplicate implementations
   - Update all references to use canonical version
   - Add migration guide for any external integrations

4. **Phase 4: Testing** (30 minutes)
   - Verify all OAuth flows still work
   - Test admin OAuth
   - Test API OAuth
   - Test session management

**Estimated Total Effort:** 2-3 hours
**Risk Level:** MEDIUM (requires careful migration, affects authentication)
**Protocol:** MEDIUM RISK deployment checklist required

---

## When to Address

**NOT NOW:** Current bug fix is urgent (production down)
**AFTER:** Bug fix is stable in production for 1 week
**SCHEDULE:** Post-mortem review on November 4, 2025

**Trigger for Action:**
- If another OAuth bug occurs due to duplication
- If new OAuth features are needed
- If intern project requires SSO integration (scheduled)

---

## Notes

- All three implementations currently use `/auth/google/callback/` as of October 28, 2025
- Google Console redirect URI must remain: `https://sso.barge2rail.com/auth/google/callback/`
- Any consolidation work should follow BARGE2RAIL_CODING_CONVENTIONS_v1.2.md
- Document decision in ADR (Architecture Decision Record) if consolidation approach chosen

---

**Status:** DOCUMENTED - No immediate action required
**Next Review:** November 4, 2025 (post-mortem)
