# Django SSO - Claude Code Instructions
## Last Updated: October 4, 2025 by The Bridge

---

## Project Context

**Business Domain:** Authentication system for small logistics company (barge2rail.com)
**Primary Users:** Office staff, field technicians, future: suppliers/customers
**Operational Reality:** 
- Interrupt-driven environment (operational emergencies take priority)
- ADHD-friendly design required (15-minute work blocks, clear checkpoints)
- Seasonal patterns (river conditions affect usage patterns)
- Small team, limited technical expertise beyond single technical lead

**Critical Constraints:**
- This SSO system blocks ALL future development (PrimeTrade, database consolidation, etc.)
- Authentication failure = complete business shutdown (no fallback currently)
- Must work on mobile (field technicians accessing remotely)
- Session management for long-duration work (not typical short sessions)

---

## Architecture Overview

**Stack:** Django 4.2 + Django REST Framework + PostgreSQL
**Deployment:** Render PaaS with Docker
**Domain:** sso.barge2rail.com (custom domain, auto-SSL via Render)
**Authentication:** OAuth v2 with Google Workspace (all staff have Google accounts)

**Key Architectural Decisions:**

1. **SSO-First Architecture** (October 2025)
   - Rationale: Centralized authentication before building individual systems
   - Impact: All future systems must integrate with this SSO
   - Why: Prevents user management fragmentation, enables seamless workflows

2. **Google Workspace OAuth v2** (October 2025)
   - Rationale: Staff already use Google accounts, no new passwords to manage
   - Impact: Tied to Google Workspace availability
   - Why: Reduces support overhead, familiar to users, automatic offboarding when Google account disabled

3. **Render PaaS over AWS** (October 2025)
   - Rationale: Simpler deployment, lower cognitive overhead
   - Impact: ~$20/month hosting cost, limited to Render's capabilities
   - Why: Small team can't maintain complex infrastructure

4. **Independent Modules Approach** (October 2025)
   - Rationale: SSO + separate applications (PrimeTrade, Database, etc.) vs monolith
   - Impact: Each system deployed independently
   - Why: Reduces blast radius of failures, allows incremental development

---

## Security Requirements

### Authentication
- **OAuth v2 with Google Workspace ONLY** - no other auth methods
- **Session timeout MUST be configured** (not Django default)
- **Token refresh mechanism REQUIRED** for long sessions (logistics work is not quick)
- **Rate limiting on auth endpoints** (use django-ratelimit) - prevent brute force
- **CSRF protection enabled** - no exceptions

### Data Protection
- **Sensitive data:** User emails, OAuth tokens, session data
- **Protection:** Server-side only, never in client JavaScript, never in logs
- **Tokens:** Store refresh tokens server-side, never expose in client code

### Known Vulnerabilities to Watch For
- **OAuth redirect_uri mismatch** - Must match Google Console exactly (trailing slashes matter)
- **Session hijacking** - Secure cookies, HTTPS only, proper timeout
- **CSRF attacks** - Trusted origins must be configured
- **Token exposure in logs** - Never log access_token, refresh_token, or id_token payloads

---

## MANDATORY SECURITY RULES

### Critical Security & Quality
1. **Authorized scope only:** change exactly what's requested; no drive-by edits
2. **Dependencies:** when adding imports, update `requirements.txt` (Django 4.2 compatible)
3. **No placeholders in code:** never commit example keys; use env vars; update `.env.example`
4. **Question vs. code:** answer questions with analysis; modify code only on explicit requests
5. **No guessing:** if API/versions/paths uncertain, STOP and ask
6. **Secrets:** never in client/templates/static/logs/tests; redact tokens/IDs
7. **Capability honesty:** if task needs infra you can't access, say so
8. **Preserve behavior:** fix bugs without changing requirements unless told
9. **Evidence-based:** cite file/lines when claiming something exists
10. **No hardcoded examples in prod paths**
11. **Logging:** add useful INFO/WARN/ERROR; **no tokens/PII**; include context

### Django/OAuth Conventions
- **SSL/Proxy:** `SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO','https')`
- **CSRF:** `CSRF_TRUSTED_ORIGINS = ['https://sso.barge2rail.com']` (no wildcards)
- **Redirect URI:** build from `BASE_URL` helper; must match Google Console exactly
- **Google OAuth:** v2 authorize endpoint; token endpoint `https://oauth2.googleapis.com/token`
- **OAuth params:** `access_type=offline`; use `prompt=consent` for refresh tokens
- **Templates/JS:** never embed client IDs/secrets
- **Logging OAuth:** never log raw tokens; log error categories and correlation IDs

---

## Development Standards

**Code Style:**
- PEP 8 for Python
- Descriptive variable names (no single letters except loop indices)
- Comments for business logic (not obvious code)
- Docstrings for public functions

**Testing Requirements:**
- Minimum coverage: 70% for new code
- Required test types: unit tests for business logic, integration tests for OAuth flow
- All new auth features MUST include: functional tests that non-technical humans can execute

**Commit Standards:**
- Descriptive commit messages
- Reference issue/task if applicable
- PRs require approval from The Bridge for MEDIUM+ risk changes

---

## Patterns That Work Here

### Pattern 1: OAuth Integration
**Use Case:** Any system requiring authentication
**Implementation:**
```python
# Redirect to SSO
redirect_url = f"{settings.BASE_URL}/auth/google/login"

# Handle callback
# Use helper function for redirect_uri consistency
redirect_uri = google_redirect_uri()
```
**Rationale:** Centralized auth reduces complexity, staff already familiar with Google login

### Pattern 2: ADHD-Friendly Error Messages
**Use Case:** Any user-facing error
**Implementation:**
- Short, clear messages (1 sentence max)
- Actionable next steps ("Click here to retry" not "An error occurred")
- No technical jargon
- Visual indicators (color, icons)
**Rationale:** Users are often mid-task when interrupted, need to resume quickly

### Pattern 3: Mobile-First Forms
**Use Case:** Any data entry interface
**Implementation:**
- Large touch targets (minimum 44px)
- Minimal typing (dropdowns, checkboxes over text fields)
- Autofill enabled
- Save progress automatically
**Rationale:** Field technicians use phones, often with gloves, in vehicles

---

## Patterns That Don't Work Here

### Anti-Pattern 1: Complex Multi-Step Wizards
**What:** UIs with many steps, "Next" buttons, progress bars
**Why Avoid:** Users get interrupted mid-flow, lose progress, frustration
**Use Instead:** Single-page forms with auto-save, clear sections

### Anti-Pattern 2: Assumed Continuous Sessions
**What:** Short session timeouts, no token refresh, logout after inactivity
**Why Avoid:** Logistics work is long-duration with interruptions (phone calls, emergencies)
**Use Instead:** Long sessions with refresh tokens, graceful re-authentication

### Anti-Pattern 3: Technical Error Messages
**What:** Stack traces, technical jargon, "Contact system administrator"
**Why Avoid:** No system administrator, technical lead is doing operational work
**Use Instead:** Clear user-friendly messages with self-service recovery

---

## Integration Points

### System 1: PrimeTrade (Future)
**Purpose:** Primary logistics application (replacement for Google Sheets)
**Integration Method:** OAuth token validation, shared user identity
**Critical Dependencies:** If SSO fails, PrimeTrade cannot authenticate users

### System 2: Database Consolidation (Future - Intern Project)
**Purpose:** Unified customer/supplier database
**Integration Method:** SSO for staff access, API tokens for programmatic access
**Critical Dependencies:** User roles and permissions managed here

### System 3: Google Workspace
**Purpose:** Identity provider, email, calendar integration
**Integration Method:** OAuth v2, Google APIs for calendar/email features
**Critical Dependencies:** Google outage = authentication outage (no mitigation currently)

---

## Common Pitfalls

### 1. OAuth Redirect URI Mismatch
**Symptom:** `redirect_uri_mismatch` error from Google
**Root Cause:** Exact URL matching required (protocol, domain, path, trailing slash)
**Solution:** Use `google_redirect_uri()` helper function consistently
**Prevention:** Never hardcode redirect URIs, always use helper

### 2. Missing Session Timeout Configuration
**Symptom:** Users logged out mid-work, lose progress
**Root Cause:** Django default session timeout too short for logistics workflows
**Solution:** Configure `SESSION_COOKIE_AGE` appropriately (consider use case)
**Prevention:** Include session testing in functional tests

### 3. Token Exposure in Logs
**Symptom:** OAuth tokens visible in application logs
**Root Cause:** Logging entire request/response objects
**Solution:** Redact sensitive fields before logging
**Prevention:** Use structured logging with explicit field inclusion (not entire objects)

### 4. CSRF Failures After Deployment
**Symptom:** POST requests fail with CSRF errors in production
**Root Cause:** `CSRF_TRUSTED_ORIGINS` not configured for production domain
**Solution:** Add `https://sso.barge2rail.com` to `CSRF_TRUSTED_ORIGINS`
**Prevention:** Test with production-like environment before deploying

---

## Deployment Context

**Environment Variables (Critical):**
- `BASE_URL` - Used for OAuth redirect URI construction (must match domain)
- `GOOGLE_CLIENT_ID` - OAuth client ID from Google Console
- `GOOGLE_CLIENT_SECRET` - OAuth client secret (NEVER commit)
- `SECRET_KEY` - Django secret key for sessions/crypto (NEVER commit)
- `DEBUG` - Must be `False` in production
- `ALLOWED_HOSTS` - Must include `sso.barge2rail.com`

**Deployment Checklist:**
1. Verify environment variables set in Render
2. Run migrations: `python manage.py migrate`
3. Collect static files: `python manage.py collectstatic --noinput`
4. Verify OAuth redirect URI in Google Console matches production URL
5. Test authentication flow manually
6. Verify error logging is working
7. Check session timeout behavior

**Rollback Procedure:**
1. Render dashboard → Rollback to previous deployment
2. Verify authentication works
3. Check error logs for issues
4. Estimated recovery time: 5-10 minutes

---

## Business Logic Quirks

### Seasonal Patterns
- **River conditions:** Winter freeze affects barge operations (lower usage December-February)
- **Peak season:** Spring/Fall (March-May, September-November) = higher load
- **Emergency spikes:** Weather events cause sudden activity bursts (unpredictable)

### Operational Constraints
- **Interrupt-driven work:** Phone calls, emergencies disrupt workflows constantly
- **Mobile access:** Field technicians on boats, in vehicles, spotty connectivity
- **Non-technical users:** Office staff have basic computer skills, need simple interfaces
- **Context switching:** Users juggle multiple tasks, need clear "where was I?" cues

---

## Testing Philosophy

**What Gets Tested:**
- **Critical:** All authentication flows (login, logout, callback, token refresh)
- **Critical:** Data integrity operations (user creation, session management)
- **Required:** Business logic (role management, permissions)
- **Nice to have:** UI interactions (can be manual)

**How to Test:**
- **Functional tests:** Non-technical humans can execute (documented in test plan)
- **Observable behavior:** Test what users see/experience, not implementation details
- **Edge cases:** Logistics-specific scenarios (long sessions, interruptions, mobile access)

**Test Coverage:**
- Minimum 70% for new code
- 100% for authentication/security code
- Functional tests for all user-facing features

---

## Recent Changes & Lessons Learned

**October 4, 2025: God Mode Shell Fix**
**What:** Fixed bash/zsh incompatibility in shell configuration
**Why:** Claude Code claimed "clean loading" but verbose output remained
**Lesson:** Always verify with functional tests, not just AI claims
**Impact:** Reinforced need for independent verification (The Bridge reviews CC's work)

**October 4, 2025: Safety System Validation**
**What:** Proved three-perspective review catches AI oversights
**Why:** Single AI (Claude Code) missed edge case, second AI (The Bridge) caught it
**Lesson:** MEDIUM+ risk work requires multiple AI perspectives
**Impact:** Established mandatory three-perspective review for all MEDIUM+ risk changes

---

## Working With The Bridge

**The Bridge provides:**
- Strategic direction and architectural decisions (documented above)
- Independent code review for MEDIUM+ risk work
- Risk assessment and deployment protocols (HIGH RISK for this project)
- Pattern library and institutional knowledge (see Patterns sections)
- Functional test generation (tests non-technical humans can execute)

**You (Claude Code) provide:**
- Tactical implementation within these guidelines
- Multi-file refactoring and repository operations
- Adherence to patterns and security rules documented here
- Evidence-based claims (cite files/lines)

**When uncertain:**
1. Check this document first (most questions answered here)
2. Reference The Bridge if architectural decision needed
3. **Never assume** - ask for clarification rather than guessing
4. Provide options with trade-offs (let human/Bridge decide)

**Communication with The Bridge:**
- Output: Numbered unified diffs + exact shell commands + 1-line test plan
- Be explicit about what you changed and why
- Flag any deviations from patterns documented here
- Suggest documentation updates if you discover gaps

---

## Response/Workflow Protocols

**Deliverables:**
- Numbered unified diffs
- Exact shell commands (with working directory)
- One-line test plan

**New config:**
- Update `.env.example` (no secrets)
- Update README snippets
- Document in this file if architectural

**Tests/docs:**
- Add minimal tests/docs when touching security/auth paths
- Functional tests for user-facing changes

**Unsure? STOP, ask, and wait.**

---

## Pre-PR Checklist (MANDATORY)

- [ ] Only requested files changed; no unrelated edits
- [ ] New imports reflected in `requirements.txt`
- [ ] `.env.example` updated (no secrets); docs updated
- [ ] CSRF/SSL/OAuth conventions upheld
- [ ] Useful logging added/kept; no tokens/PII in logs
- [ ] Patterns from this document followed
- [ ] Security rules followed
- [ ] Provide diffs + commands + 1-line test plan
- [ ] For MEDIUM+ risk: Three-perspective review completed

---

## Session Permissions Header (paste atop every AI prompt)

SESSION PERMISSIONS
- You may: read/clone repo, create feature branches, open PRs, write Dockerfile/render.yaml, edit server-only code, add tests/docs
- You must not: expose secrets, change business logic without approval, touch unrelated files, merge PRs without explicit CTO approval
- Ask ONLY if business rules are missing. Otherwise proceed.
- Output: numbered unified diffs, exact shell commands (with working directory), and a 1-line test plan

---

## Version History

- **v2.0 - October 4, 2025** - Enhanced by The Bridge
  - Added business context (logistics, operational reality)
  - Documented architectural decisions
  - Added patterns library (work/don't work)
  - Added integration points
  - Added lessons learned (God Mode, Safety System)
  - Added testing philosophy
  - Integrated with The Bridge workflow
  - Maintained all original security rules (v1.0)

- **v1.0 - [Previous Date]** - Initial creation
  - Security-focused rules
  - OAuth conventions
  - Pre-PR checklist
