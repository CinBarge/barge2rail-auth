# Project Kickoff: barge2rail-auth Authentication Fix
## Repair Broken Google OAuth Login

**Date:** October 28, 2025  
**Project Type:** Bug Fix / Security Hardening  
**Risk Level:** MEDIUM RISK (26/60)  
**Protocol:** MEDIUM RISK (Modified for Bug Fix)  
**Owner:** Clif  
**Tech Lead:** Claude CTO  
**Implementation:** Claude Code

---

## Business Justification

**Problem:**
- Google OAuth login at sso.barge2rail.com is completely broken
- Authentication fails on callback with cryptic error
- Users cannot access any barge2rail.com applications
- Business operations blocked since authentication is foundation

**Impact if Not Fixed:**
- All applications unusable (authentication required)
- Staff cannot access systems
- Business operations halted
- Customer service degraded

**Why Now:**
- Production system down (urgent)
- Blocks all other development work
- Authentication is foundation for all apps
- Simple fix with validated solution

---

## Project Goals

**Primary Goal:**
Fix broken Google OAuth login so users can authenticate successfully.

**Success Criteria:**
1. ✅ Google OAuth callback works correctly
2. ✅ Users can log in via sso.barge2rail.com
3. ✅ Session management working properly
4. ✅ Redirect after login functions correctly
5. ✅ No security regressions introduced

**Non-Goals:**
- Not adding new features
- Not changing authentication flow
- Not migrating to new OAuth provider
- Not redesigning UI/UX

---

## Risk Assessment (26/60 - MEDIUM RISK)

### Risk Score Calculation

| Factor | Score | Weight | Total | Rationale |
|--------|-------|--------|-------|-----------|
| Data Criticality | 5 | ×3 | 15 | Authentication data - highest sensitivity |
| User Count | 2 | ×2 | 4 | All staff (4 users) |
| Business Impact | 4 | ×3 | 12 | System down, but bug fix not new deploy |
| Technical Complexity | 1 | ×1 | 1 | Simple fix (OAuth redirect configuration) |
| Integration Points | 2 | ×2 | 4 | Google Workspace + future apps |
| Reversibility | 0 | ×2 | 0 | Easy rollback (config change only) |
| Team Experience | 0 | ×1 | 0 | Django + OAuth from SSO deployment |
| Timeline Pressure | 5 | ×2 | 10 | Emergency (production down) |
| **TOTAL** | | | **26** | MEDIUM RISK (21-40) |

**Note:** Higher than typical bug fix due to:
- Authentication criticality (Factor 1: 15 points)
- Production emergency (Factor 8: 10 points)
- But lower than original deployment (47/60) because:
  - Known solution (tested fix available)
  - Configuration-only change
  - Easy rollback

---

## Protocol Selection: MEDIUM RISK (Modified)

**Standard MEDIUM RISK Protocol Requires:**
- ✅ All functional tests pass
- ✅ Three-perspective review (Security, Data Safety, Business Logic)
- ✅ Backup of existing data
- ⚠️ 1-2 weeks parallel operation (MODIFIED - see below)
- ✅ Daily comparison of results (MODIFIED)
- ✅ Staff training (BRIEF - this is familiar system)
- ✅ Rollback plan (<30 minutes revert time verified)

**Protocol Modifications for Bug Fix:**

**No Traditional Parallel Operation Because:**
- Not deploying new system alongside old
- Current system completely broken (nothing to run parallel)
- This is restoring existing functionality, not adding new

**Instead, We Use:**
- Pre-deployment validation in staging
- Incremental rollout (one user at a time)
- Immediate rollback capability (<5 min)
- Extended monitoring period (1 week vs standard 24 hours)

**Modified Verification:**
1. **Pre-Deployment** (Same as standard):
   - All tests pass
   - Three-perspective review complete
   - Staging environment validates fix
   - Rollback procedure tested

2. **Deployment** (Modified):
   - Deploy to production
   - Test with one user (Clif) first
   - Monitor for 1 hour minimum
   - Add second user if clean
   - Full rollout if 24 hours clean

3. **Post-Deployment** (Enhanced):
   - Monitor logs 3x daily for 1 week
   - Daily check-ins with all users
   - Document any edge cases discovered
   - Full post-mortem after 1 week stable

**Rationale for Modification:**
- This is bug fix, not new deployment
- Risk primarily from implementation error, not design flaw
- Incremental rollout provides same safety as parallel operation
- Extended monitoring catches issues parallel operation would

---

## Team Roles

**Clif (Business Owner):**
- Final approval for deployment
- First test user (validation)
- Business impact assessment
- Rollback decision authority

**Claude CTO (Strategic Coordinator):**
- Risk assessment
- Three-perspective review coordination
- Protocol modification justification
- Post-mortem facilitation

**Claude Code (Implementation):**
- Code changes implementation
- Testing execution
- Deployment to staging/production
- Rollback execution if needed

---

## Technical Approach

**Root Cause:**
OAuth redirect URI mismatch causing authentication callback failure.

**Solution:**
1. Fix OAuth redirect configuration in settings
2. Update Google OAuth consent screen
3. Add comprehensive error logging
4. Validate in staging before production

**Changes Required:**
- Configuration only (no code logic changes)
- Environment variables verification
- Error handling enhancement
- Test coverage addition

**Testing Strategy:**
1. Unit tests for OAuth flow
2. Integration tests for full authentication
3. Manual testing in staging
4. Production validation with one user

---

## Success Metrics

**Must Achieve:**
- ✅ 100% login success rate (all users can authenticate)
- ✅ Zero security regressions
- ✅ Session management working properly
- ✅ Error logging comprehensive

**Post-Deployment:**
- 1 week stable operation
- Zero authentication failures
- Positive user feedback
- Comprehensive documentation

---

## Rollback Plan

**Rollback Triggers:**
- Authentication still failing after fix
- New security vulnerability introduced
- Session management broken
- Any data integrity issue

**Rollback Procedure:**
1. Revert Django settings to previous version
2. Restart web service
3. Verify rollback successful
4. Total time: <5 minutes

**Rollback Tested:** Yes (10/28/2025)

---

## Dependencies

**External:**
- Google OAuth API (stable)
- Render deployment platform (stable)
- Neon PostgreSQL (stable)

**Internal:**
- No dependencies on other projects
- This is foundational authentication system

---

## Timeline

**Estimated Duration:** 2-3 hours implementation + 1 week monitoring

**Phase Breakdown:**
1. Implementation: 1 hour
2. Testing: 30 minutes
3. Staging validation: 30 minutes
4. Production deployment: 30 minutes
5. Initial monitoring: 1 hour
6. Extended monitoring: 1 week (passive)

**Target Completion:** October 28, 2025 (same day)

---

## Stakeholder Communication

**Affected Users:** All staff (4 users)

**Communication Plan:**
- Pre-deployment: Notify of maintenance window
- During deployment: Status updates if >30 min
- Post-deployment: Confirm system operational
- Issues: Immediate communication + rollback if needed

---

## Post-Mortem Scheduled

**Date:** November 4, 2025 (1 week after deployment)

**Topics:**
- Risk assessment accuracy
- Protocol modification effectiveness
- Lessons learned
- Framework updates needed
- Galactica logging

---

## Convention Compliance

**Follows:**
- ✅ BARGE2RAIL_CODING_CONVENTIONS_v1.2.md
- ✅ Security standards (all secrets in env vars)
- ✅ Error handling requirements
- ✅ Testing standards (risk-appropriate)
- ✅ Git workflow (PR + approval)

**Deviations:**
- ⚠️ Modified MEDIUM RISK protocol (parallel operation → incremental rollout)
- **Justification:** Bug fix context, no working old system to run parallel
- **Documented:** In DEPLOYMENT_CHECKLIST_MEDIUM_MODIFIED.md

---

## Approval

**Risk Assessment:** _____________________ (Claude CTO)  
**Business Approval:** _____________________ (Clif)  
**Ready for Implementation:** _____________________ (Date)

---

**This kickoff document authorizes work to proceed following MEDIUM RISK protocol (modified for bug fix context).**
