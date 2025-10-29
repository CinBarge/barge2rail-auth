# Modified MEDIUM RISK Deployment Checklist
## barge2rail-auth Authentication Fix

**Project:** OAuth Login Repair  
**Risk Level:** MEDIUM RISK (26/60)  
**Protocol:** MEDIUM RISK (Modified for Bug Fix)  
**Date Started:** October 28, 2025

---

## PROTOCOL MODIFICATION NOTICE

**Standard MEDIUM RISK Protocol:**
- Requires 1-2 weeks parallel operation (old + new system running together)
- Daily comparison of results between systems
- Gradual cutover after validation

**Why Modified:**
- ❌ No working "old system" to run in parallel (authentication completely broken)
- ❌ This is bug fix, not new deployment
- ✅ Instead: Incremental rollout + enhanced monitoring
- ✅ Same safety goals achieved through different mechanism

**Modification Approved By:** Clif (Business Owner)  
**Justification Documented In:** PROJECT_KICKOFF.md

---

## Prerequisites (Must Complete Before Starting)

### Code Quality
- [ ] All existing tests pass (run `pytest`)
- [ ] New tests written for OAuth flow
- [ ] Code follows BARGE2RAIL_CODING_CONVENTIONS_v1.2.md
- [ ] Pre-commit hooks passing
- [ ] No secrets in code (all in environment variables)

### Environment Validation
- [ ] Staging environment configured
- [ ] Production environment variables verified
- [ ] Google OAuth consent screen updated
- [ ] Redirect URIs match in all environments

### Review Completed
- [ ] Security review (HIGH confidence required)
- [ ] Data safety review (MEDIUM+ confidence required)
- [ ] Business logic review (MEDIUM+ confidence required)
- [ ] All three perspectives at MEDIUM+ confidence

### Preparation
- [ ] Backup of current configuration
- [ ] Rollback procedure tested (<5 min revert time verified)
- [ ] Monitoring/logging configured
- [ ] All stakeholders notified of deployment window

---

## Pre-Deployment Security Review

### Authentication Security (HIGH Confidence Required)
- [ ] OAuth flow cannot be bypassed
- [ ] Session management secure
- [ ] Tokens handled properly (not exposed in logs/URLs)
- [ ] Redirect URI validation correct
- [ ] HTTPS enforced everywhere
- [ ] CSRF protection maintained
- [ ] No session fixation vulnerabilities
- [ ] **Confidence Level:** MEDIUM / HIGH (circle one, HIGH required)

**Security Issues Found:** _____________  
**Resolution:** _____________

---

## Pre-Deployment Data Safety Review

### Data Protection (MEDIUM+ Confidence Required)
- [ ] Cannot corrupt user accounts
- [ ] Session data managed safely
- [ ] Database operations safe
- [ ] Audit trail exists (who logged in when)
- [ ] No data leakage in error messages
- [ ] User data validated properly
- [ ] **Confidence Level:** MEDIUM / HIGH (circle one)

**Data Safety Issues Found:** _____________  
**Resolution:** _____________

---

## Pre-Deployment Business Logic Review

### Functionality (MEDIUM+ Confidence Required)
- [ ] Login flow matches expected workflow
- [ ] Error messages clear to users
- [ ] Redirect after login correct
- [ ] Session timeout appropriate
- [ ] Logout works properly
- [ ] Edge cases handled (expired tokens, network failures)
- [ ] **Confidence Level:** MEDIUM / HIGH (circle one)

**Business Logic Issues Found:** _____________  
**Resolution:** _____________

---

## Staging Validation

**Staging Environment:** https://barge2rail-auth-staging.onrender.com

### Test Scenarios
- [ ] Fresh login (no existing session)
- [ ] Login with existing Google account
- [ ] Logout + re-login
- [ ] Expired session handling
- [ ] Invalid redirect handling
- [ ] Network failure during OAuth flow
- [ ] Multiple browser tabs
- [ ] Different browsers (Chrome, Firefox, Safari)

**Staging Test Date:** _____________  
**All Scenarios Passed:** YES / NO  
**Issues Found:** _____________  
**Resolution:** _____________

---

## Production Deployment

### Pre-Deployment Final Checks
- [ ] All staging tests passed
- [ ] Three-perspective reviews complete (all MEDIUM+)
- [ ] Rollback procedure ready
- [ ] Monitoring dashboard open
- [ ] Stakeholders notified

### Deployment Steps
- [ ] **Step 1:** Deploy to production
- [ ] **Step 2:** Restart web service
- [ ] **Step 3:** Verify deployment succeeded (check logs)
- [ ] **Step 4:** Run smoke test (basic auth flow)

**Deployment Time:** ___________  
**Deployment Status:** SUCCESS / FAILED

---

## Incremental Rollout (Replaces Parallel Operation)

**This replaces standard "1-2 weeks parallel operation" for bug fix context.**

### Phase 1: Single User Validation (Day 1, Hour 1-2)

**Test User:** Clif (Business Owner)

**Validation Checklist:**
- [ ] User can access login page
- [ ] Google OAuth initiates correctly
- [ ] Callback completes successfully
- [ ] Session created properly
- [ ] Dashboard accessible
- [ ] Logout works
- [ ] Re-login works
- [ ] No errors in logs

**Phase 1 Time:** ___________ (1-2 hours)  
**Status:** PASS / FAIL  
**Issues:** _____________

**If FAIL → Immediate rollback**

---

### Phase 2: Second User Addition (Day 1, Hour 3-24)

**After 1 Hour Clean in Phase 1**

**Test User 2:** ___________ (Staff Member)

**Validation Checklist:**
- [ ] Second user can log in
- [ ] No conflicts with first user's session
- [ ] Both users can access applications
- [ ] No errors in logs
- [ ] Performance acceptable

**Phase 2 Time:** ___________ (started after 1 hour clean)  
**Status:** PASS / FAIL  
**Issues:** _____________

**If FAIL → Rollback, analyze, redeploy**

---

### Phase 3: Full Rollout (Day 2+)

**After 24 Hours Clean in Phase 2**

**All Users:** Remaining staff (2 users)

**Validation Checklist:**
- [ ] All users notified system ready
- [ ] All users can log in successfully
- [ ] No performance degradation
- [ ] No errors in logs
- [ ] Session management working for all

**Phase 3 Time:** ___________ (started after 24 hours clean)  
**Status:** PASS / FAIL  
**Issues:** _____________

---

## Enhanced Monitoring (Replaces Daily Comparison)

**This replaces "daily comparison of old vs new" for bug fix context.**

### Daily Monitoring Checklist (Days 1-7)

**Day:** _____ / Date: _____

**Morning Check (9 AM):**
- [ ] Review error logs (check for auth failures)
- [ ] Check user sessions (active/expired counts)
- [ ] Verify no performance issues
- [ ] Confirm all users can access

**Afternoon Check (2 PM):**
- [ ] Review error logs again
- [ ] Check for any user complaints
- [ ] Monitor session management
- [ ] Verify system stability

**Evening Check (6 PM):**
- [ ] Final error log review
- [ ] Confirm no issues reported
- [ ] Document any quirks discovered
- [ ] Plan fixes if needed

**Issues Found Today:**
1. _________________________________
2. _________________________________
3. _________________________________

**Status:** CLEAN / ISSUES (circle one)

---

### Weekly Summary

**Week:** 1 (dates: _____ to _____)

- [ ] Total days of monitoring: 7
- [ ] Days with zero issues: _____
- [ ] Critical issues found: _____ (must be 0)
- [ ] Minor issues found: _____
- [ ] All issues resolved: YES / NO
- [ ] Staff feedback: POSITIVE / MIXED / NEGATIVE

**Notes:**
_______________________________________________
_______________________________________________

---

## Cutover Decision (After 1 Week Clean)

**Only proceed to "mission complete" if ALL true:**

- [ ] Minimum 1 week monitoring complete (7 days)
- [ ] Zero critical authentication failures
- [ ] All users can access systems
- [ ] Minor issues understood and acceptable
- [ ] Staff comfortable with system
- [ ] No security concerns identified

**Date of Cutover Decision:** _____  
**Decision:** COMPLETE / EXTEND MONITORING

---

## Rollback Triggers

**Immediate Rollback If:**
- Any authentication completely fails
- Security vulnerability discovered
- Session management broken
- Any user unable to access system for >1 hour

**Planned Rollback If:**
- Consistent usability issues after 3 days
- Staff reports system less reliable than expected
- Subtle bugs affecting workflow

**Rollback Procedure:**
1. Revert configuration to previous version
2. Restart web service
3. Verify rollback successful
4. Notify all users
5. Document what failed

**Rollback Execution Time:** <5 minutes (tested)

---

## Post-Deployment (1 Week)

### Week 1 Status
- [ ] Daily monitoring completed (7 days)
- [ ] Zero critical issues
- [ ] Staff comfortable with system
- [ ] Documentation updated
- [ ] Post-mortem scheduled

**Week 1 Complete:** ___________  
**Status:** SUCCESS / ISSUES

---

## Post-Mortem

**Scheduled Date:** November 4, 2025 (1 week after deployment)

**Topics to Cover:**
- [ ] Planning vs reality (risk assessment accuracy)
- [ ] Protocol modification effectiveness
- [ ] Incremental rollout vs parallel operation comparison
- [ ] What went well
- [ ] What could improve
- [ ] Patterns for future bug fixes
- [ ] Framework updates needed
- [ ] Galactica logging complete

**Post-Mortem Complete:** _____  
**Lessons Logged:** _____

---

## Sign-Off

**Initial Deployment:** ___________________  
**Phase 1 (Single User) Complete:** ___________________  
**Phase 2 (Two Users) Complete:** ___________________  
**Phase 3 (All Users) Complete:** ___________________  
**1 Week Monitoring Complete:** ___________________  
**Post-Mortem Complete:** ___________________  
**Business Owner Approval:** ___________________

---

## Convention Compliance

**Modified Protocol Justification:**
- Standard MEDIUM RISK requires parallel operation
- Not possible here (no working old system)
- Incremental rollout provides equivalent safety
- Enhanced monitoring catches issues parallel operation would
- Same risk mitigation achieved through different mechanism

**Documented In:**
- PROJECT_KICKOFF.md (Protocol Selection section)
- This checklist (Protocol Modification Notice at top)

**Approval:**
- Business Owner: Clif
- Strategic Coordinator: Claude CTO
- Implementation: Claude Code

---

**This modified protocol provides same safety goals as standard MEDIUM RISK protocol, adapted for bug fix context.**
