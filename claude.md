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

## Common Django Commands

### Development
- `python manage.py runserver` - Start dev server (http://localhost:8000)
- `python manage.py shell` - Django Python shell with models loaded
- `python manage.py dbshell` - Direct PostgreSQL shell access

### Database
- `python manage.py makemigrations` - Create migration files from model changes
- `python manage.py migrate` - Apply migrations to database
- `python manage.py showmigrations` - Show migration status
- `python manage.py sqlmigrate app_name migration_number` - Show SQL for a migration

### Testing
- `python manage.py test` - Run full test suite
- `python manage.py test app_name` - Run tests for specific app
- `python manage.py test --keepdb` - Run tests reusing test DB (faster)
- `python manage.py test --parallel` - Run tests in parallel (faster for large suites)

### User Management
- `python manage.py createsuperuser` - Create Django admin user
- `python manage.py changepassword <username>` - Reset user password

### Deployment (Render)
- **Trigger:** Git push to `main` branch ? automatic deployment
- **Render runs:** `python manage.py migrate` then `python manage.py collectstatic --noinput`
- **Environment variables:** Set in Render dashboard (never commit secrets)
- **Logs:** View in Render dashboard ? Logs tab
- **Rollback:** Render dashboard ? Manual Deploy ? select previous commit

### Debugging
- `python manage.py check` - Validate Django project (catch common configuration errors)
- `python manage.py check --deploy` - Additional production-readiness checks (settings validation)
- `python manage.py diffsettings` - Show which settings differ from Django defaults

### Static Files
- `python manage.py collectstatic` - Gather static files for deployment
- `python manage.py collectstatic --noinput` - Non-interactive version (for CI/CD)

### Django Shell Utilities
```python
# Common shell operations
from django.contrib.auth import get_user_model
User = get_user_model()

# List all users
User.objects.all()

# Find specific user
User.objects.get(email='user@barge2rail.com')

# Test OAuth token
from allauth.socialaccount.models import SocialToken
SocialToken.objects.filter(account__user__email='user@barge2rail.com')
```

**Note:** All commands assume you're in the project root (`/Users/cerion/Projects/barge2rail-auth`) with virtual environment activated.

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

## Error Handling Philosophy

### Diagnose First, Fix Second
**When encountering a bug or error:**
1. **Analyze the root cause step-by-step** - Don't jump to solutions
2. **Check assumptions** - What did we assume that might be wrong?
3. **Trace the data flow** - Where does the bad data come from?
4. **Review relevant code paths** - What else touches this functionality?
5. **Use Django's error messages** - They're usually accurate and helpful

**Example approach:**
```
Error: "redirect_uri_mismatch" from Google OAuth

Step 1: What is the actual redirect_uri being sent?
Step 2: What is configured in Google Console?
Step 3: Do they match exactly (protocol, domain, path, trailing slash)?
Step 4: Is BASE_URL environment variable set correctly?
Step 5: Is google_redirect_uri() helper being used consistently?
```

### Graceful Error Handling

**For External Dependencies (OAuth, APIs):**
```python
# DO: Wrap in try/except with specific exceptions
try:
    token_response = requests.post(token_url, data=token_data, timeout=10)
    token_response.raise_for_status()
except requests.Timeout:
    logger.error("OAuth token request timed out", extra={'correlation_id': correlation_id})
    return JsonResponse({'error': 'Authentication service temporarily unavailable. Please try again.'}, status=503)
except requests.HTTPError as e:
    logger.error(f"OAuth token request failed: {e.response.status_code}", extra={'correlation_id': correlation_id})
    return JsonResponse({'error': 'Authentication failed. Please try again or contact support.'}, status=500)
```

**For Database Operations:**
```python
# DO: Use transactions for multi-step operations
from django.db import transaction

try:
    with transaction.atomic():
        user = User.objects.create(email=email)
        profile = Profile.objects.create(user=user, ...)
        # All or nothing - rolls back on any error
except IntegrityError:
    logger.warning(f"Duplicate user creation attempt: {email}")
    return JsonResponse({'error': 'User already exists'}, status=409)
```

**For User-Facing Errors:**
- Return clear, actionable messages (no technical jargon)
- Use Django's messages framework for UI feedback
- Provide next steps ("Click here to retry" not just "Error occurred")
- Include correlation IDs in logs (for debugging) but not in user messages

### Logging Standards

**Use Django's logging framework:**
```python
import logging
logger = logging.getLogger(__name__)

# ERROR: Genuine errors requiring investigation
logger.error("OAuth callback failed", extra={
    'user_email': user.email,
    'error_type': 'token_exchange_failed',
    'correlation_id': correlation_id
})

# WARNING: Expected issues that might need attention
logger.warning("User attempted login with revoked Google access", extra={
    'user_email': user.email
})

# INFO: Normal operations for audit trail
logger.info("User logged in successfully", extra={
    'user_email': user.email,
    'login_method': 'google_oauth'
})
```

**Logging Rules:**
- ? **DO:** Include context (user ID, correlation ID, operation type)
- ? **DO:** Use structured logging (extra={} dict)
- ? **DO:** Log at appropriate level (ERROR/WARNING/INFO)
- ? **DON'T:** Log tokens, passwords, or PII (NEVER)
- ? **DON'T:** Log entire request/response objects (may contain secrets)
- ? **DON'T:** Use ERROR level for expected flows (use INFO or WARNING)

### No Silent Failures

**BAD - Swallows exception:**
```python
try:
    user = User.objects.get(email=email)
except User.DoesNotExist:
    pass  # ? Silent failure - what happens now?
```

**GOOD - Handles explicitly:**
```python
try:
    user = User.objects.get(email=email)
except User.DoesNotExist:
    logger.warning(f"Login attempt for non-existent user: {email}")
    return JsonResponse({'error': 'Invalid credentials'}, status=401)
```

**Use Django's built-in exceptions:**
- `Http404` - For not-found scenarios (triggers 404 page)
- `PermissionDenied` - For authorization failures (triggers 403 page)
- `SuspiciousOperation` - For security issues (logged and returns 400)

### OAuth-Specific Error Handling

**Common OAuth errors and responses:**
```python
# redirect_uri_mismatch
# Cause: Mismatch between request and Google Console
# Fix: Use google_redirect_uri() helper consistently
# User message: "Configuration error. Please contact support."

# invalid_grant
# Cause: Refresh token expired or revoked
# Fix: Clear tokens, redirect to re-authenticate
# User message: "Your session has expired. Please log in again."

# access_denied
# Cause: User clicked "Cancel" on Google consent screen
# Fix: Expected behavior, handle gracefully
# User message: "Login cancelled. You can try again anytime."
```

### Debugging Checklist

**When stuck on a bug:**
1. [ ] Check Django's error page (DEBUG=True locally) - full stack trace
2. [ ] Review relevant logs (filter by correlation_id or timestamp)
3. [ ] Test in Django shell - reproduce issue in isolation
4. [ ] Check database state - does data match expectations?
5. [ ] Verify environment variables - are they set correctly?
6. [ ] Check for recent changes - what changed before bug appeared?
7. [ ] Use `python manage.py check --deploy` - catches common config issues
8. [ ] Review Common Pitfalls section - is this a known issue?

**Django debugging tools:**
- `python manage.py shell` - Test models and logic interactively
- `python manage.py dbshell` - Inspect database directly
- `python manage.py diffsettings` - See non-default settings
- Django Debug Toolbar (dev only) - SQL queries, cache hits, timing

### Error Recovery Strategies

**If a solution isn't working:**
1. **Stop and reassess** - Don't keep trying random fixes
2. **Revert recent changes** - Get back to known-good state
3. **Test in isolation** - Remove complexity, test one thing at a time
4. **Check external dependencies** - Is Google OAuth down? Is database accessible?
5. **Consult documentation** - Django docs, OAuth specs, Render guides
6. **Ask for help** - Flag to The Bridge if uncertain about approach

**For production issues:**
- Have rollback plan ready (see Deployment Context section)
- Monitor error rates in Render logs
- Keep old system accessible during parallel operation
- Document issue in Common Pitfalls for future reference

---

## Deployment Context---

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
1. Render dashboard ‚Üí Rollback to previous deployment
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

## Edge Cases & Corner Cases

### Always Consider These Scenarios

**For ANY non-trivial feature, proactively list and handle edge cases.**

### Category 1: Empty/Null/Missing Data

**What to check:**
- What if the input list/queryset is empty?
- What if a required field is None/null?
- What if a string is empty ('')?
- What if a dictionary is missing expected keys?
- What if optional parameters aren't provided?

**Examples for this project:**
```python
# BAD: Assumes users exist
users = User.objects.all()
first_user = users[0]  # ? Crashes if no users

# GOOD: Handles empty case
users = User.objects.all()
if not users.exists():
    logger.warning("No users found in system")
    return JsonResponse({'error': 'No users available'}, status=404)
first_user = users.first()  # Returns None if empty (doesn't crash)
```

### Category 2: Concurrent Access & Race Conditions

**What to check:**
- What if two users modify the same data simultaneously?
- What if a user opens the app in multiple browser tabs?
- What if an OAuth callback arrives while user is already logged in?
- What if two requests try to create the same user record?

**Examples for this project:**
```python
# BAD: Race condition possible
if not User.objects.filter(email=email).exists():
    User.objects.create(email=email)  # ? Two requests might both pass check

# GOOD: Database constraint handles it
try:
    user = User.objects.create(email=email)
except IntegrityError:
    user = User.objects.get(email=email)  # Already exists, use it
```

### Category 3: Session & Authentication Edge Cases

**Critical for SSO system - what to check:**
- User revokes Google access mid-session (refresh token invalid)
- User changes Google password (invalidates all tokens)
- User clicks "login" button twice rapidly (duplicate OAuth states)
- User manually edits OAuth callback URL parameters (CSRF attempt)
- Session expires during a long form submission
- User logs in on device A, then device B (multiple active sessions)
- Token expires between page load and API call

**Examples for this project:**
```python
# Handle token refresh failure
try:
    new_token = refresh_oauth_token(refresh_token)
except OAuthTokenExpired:
    # Gracefully handle - clear session, redirect to login
    request.session.flush()
    messages.warning(request, "Your session has expired. Please log in again.")
    return redirect('login')
```

### Category 4: Input Validation & Format Issues

**What to check:**
- What if email format is invalid?
- What if a name contains special characters (O'Brien, José, ??)?
- What if input exceeds expected length (500-character company name)?
- What if numeric input is negative when should be positive?
- What if date ranges are invalid (end before start)?

**Examples for this project:**
```python
# Validate email before processing
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

try:
    validate_email(email)
except ValidationError:
    return JsonResponse({'error': 'Invalid email format'}, status=400)

# Handle special characters in names
name = name.strip()  # Remove whitespace
if len(name) > 200:
    return JsonResponse({'error': 'Name too long (max 200 characters)'}, status=400)
```

### Category 5: Network & External Service Issues

**What to check:**
- What if OAuth provider (Google) is down or slow?
- What if network request times out?
- What if API returns unexpected status code (500, 429, etc.)?
- What if database connection is lost mid-request?
- What if third-party service changes API format?

**Examples for this project:**
```python
# Handle Google API unavailability
try:
    response = requests.get(google_api_url, timeout=10)
    response.raise_for_status()
except requests.Timeout:
    logger.error("Google API request timed out", extra={'url': google_api_url})
    return JsonResponse({
        'error': 'Authentication service temporarily unavailable. Please try again in a few moments.'
    }, status=503)
except requests.RequestException as e:
    logger.error(f"Google API request failed: {str(e)}")
    return JsonResponse({'error': 'Authentication failed. Please contact support.'}, status=500)
```

### Category 6: OAuth-Specific Edge Cases

**Critical for this authentication system:**

| Edge Case | Impact | Handling |
|-----------|--------|----------|
| Redirect URI has trailing slash mismatch | OAuth fails | Use `google_redirect_uri()` helper everywhere |
| User clicks "Cancel" on Google consent | No auth granted | Expected - show friendly message, allow retry |
| OAuth state parameter missing/tampered | CSRF attack | Validate state, reject if invalid |
| Multiple OAuth callbacks for same state | Duplicate processing | Mark state as used after first callback |
| Refresh token revoked by user | Can't refresh access | Clear session, require re-authentication |
| User has no Google Workspace account | Wrong account type | Validate domain, reject non-workspace accounts |
| OAuth scopes changed in Google Console | Unexpected data access | Log and alert, may need user re-consent |

### Category 7: Data Limits & Boundaries

**What to check:**
- What if there are 10,000 users? (pagination needed)
- What if a single user has 1,000 active sessions? (cleanup needed)
- What if company name is 1,000 characters? (database limit)
- What if date is far future (year 9999)? (validation needed)
- What if numeric calculation could overflow? (use Decimal for money)

### Edge Case Testing Approach

**For any new feature:**

1. **Brainstorm edge cases** (spend 5 minutes listing scenarios)
2. **Categorize** (which of the 7 categories above apply?)
3. **Decide handling strategy** for each:
   - **Validate and reject** (with clear error message)
   - **Handle gracefully** (fallback behavior)
   - **Fail fast** (raise exception, logged)
   - **Document assumption** (if edge case intentionally not handled)

4. **Implement guards:**
```python
# Example: Login endpoint edge case guards
def login_view(request):
    # Edge case 1: Already authenticated
    if request.user.is_authenticated:
        return redirect('dashboard')

    # Edge case 2: Missing OAuth state
    state = request.GET.get('state')
    if not state:
        logger.warning("OAuth callback missing state parameter")
        return JsonResponse({'error': 'Invalid authentication attempt'}, status=400)

    # Edge case 3: Invalid/expired state
    if not validate_oauth_state(state):
        logger.warning("OAuth callback with invalid state", extra={'state': state[:20]})
        return JsonResponse({'error': 'Authentication request expired. Please try again.'}, status=400)

    # Continue with normal flow...
```

5. **Test edge cases explicitly:**
   - Add test cases for each identified edge case
   - Include in functional tests ("What happens if user clicks login twice?")
   - Document in test plan

### When to Raise Exceptions vs. Handle Gracefully

**Raise exceptions (fail fast) when:**
- Programming error (developer mistake, not user mistake)
- Configuration error (missing env var, invalid settings)
- Data corruption (database integrity violated)
- Security violation (CSRF, tampered data)

**Handle gracefully when:**
- User input error (invalid email, wrong format)
- Expected edge case (user clicks cancel, session expires)
- External service issue (Google API down, network timeout)
- Business logic condition (user already exists, insufficient permissions)

### Logistics-Specific Edge Cases

**Unique to barge2rail operations:**

- **Spotty connectivity:** Field technician loses network mid-form
  - *Handling:* Auto-save drafts, allow offline work, sync when reconnected

- **Long interruptions:** User called away for emergency, returns hours later
  - *Handling:* Long session timeouts, save work-in-progress, easy resume

- **Mobile device quirks:** iOS Safari, Android Chrome, various screen sizes
  - *Handling:* Responsive design, test on actual devices, touch-friendly UI

- **Seasonal patterns:** River freeze (winter) means different usage
  - *Handling:* System should work year-round, scale down if needed

- **Emergency scenarios:** Urgent operational issue during system use
  - *Handling:* Quick save, clear exit points, easy return to task

### Red Flags: Edge Cases You Might Miss

**?? Watch out for these commonly overlooked scenarios:**

- Unicode characters in names (José, ??, emoji)
- Time zone issues (database UTC, user local time)
- DST transitions (dates jumping forward/backward)
- Leap years (February 29)
- Very old dates (before 1900) or far future (after 2100)
- First/last element of array (off-by-one errors)
- Empty responses from external APIs
- Partial failures (some operations succeed, others fail)
- Idempotency (can same operation run twice safely?)

### Documentation Requirement

**When encountering an edge case in development:**
1. Add it to "Common Pitfalls" section with solution
2. Log to Galactica for institutional memory
3. Add test to prevent regression
4. Update this section if new category discovered

**Prefer to fail fast on bad input rather than proceeding with wrong assumptions.**

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
