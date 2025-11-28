# SSO System - Project Context
**Project:** barge2rail-auth
**Domain:** sso.barge2rail.com
**Stack:** Django 4.2 + Django REST Framework + PostgreSQL
**Deployment:** Render PaaS with Docker
**Last Updated:** October 4, 2025

**Shared Django patterns:** `../CLAUDE.md`
**Universal patterns:** `../../CLAUDE.md`

---

## Business Context

### What This Is
Authentication system for small logistics company (barge2rail.com).

### Primary Users
- Office staff (administrative work)
- Field technicians (mobile access from boats/vehicles)
- Future: suppliers/customers (external access)

### Critical Constraints
⚠️ **This SSO system blocks ALL future development** - PrimeTrade, database consolidation, and all new systems depend on this working.

⚠️ **Authentication failure = complete business shutdown** - there is currently no fallback authentication method.

⚠️ **Must work on mobile** - field technicians access remotely with spotty connectivity.

### Operational Reality
See `../../CLAUDE.md` for ADHD-friendly patterns - this context drives all UI/UX decisions for barge2rail systems.

---

## Architecture Decisions

### 1. SSO-First Architecture (October 2025)
**Rationale:** Centralized authentication before building individual systems
**Impact:** All future systems must integrate with this SSO
**Why:** Prevents user management fragmentation, enables seamless workflows

### 2. Google Workspace OAuth v2 (October 2025)
**Rationale:** Staff already use Google accounts, no new passwords to manage
**Impact:** Tied to Google Workspace availability
**Why:** Reduces support overhead, familiar to users, automatic offboarding when Google account disabled

### 3. Render PaaS over AWS (October 2025)
**Rationale:** Simpler deployment, lower cognitive overhead
**Impact:** ~$20/month hosting cost, limited to Render's capabilities
**Why:** Small team (single technical lead) can't maintain complex infrastructure

### 4. Independent Modules Approach (October 2025)
**Rationale:** SSO + separate applications (PrimeTrade, Database, etc.) vs monolith
**Impact:** Each system deployed independently
**Why:** Reduces blast radius of failures, allows incremental development

---

## Integration Points

### System 1: PrimeTrade (Future)
**Purpose:** Primary logistics application (replacement for Google Sheets)
**Integration Method:** OAuth token validation, shared user identity
**Critical Dependency:** If SSO fails, PrimeTrade cannot authenticate users
**Domain:** prt.barge2rail.com

### System 2: Database Consolidation (Future - Intern Project)
**Purpose:** Unified customer/supplier database
**Integration Method:** SSO for staff access, API tokens for programmatic access
**Critical Dependency:** User roles and permissions managed here

### System 3: Google Workspace
**Purpose:** Identity provider, email, calendar integration
**Integration Method:** OAuth v2, Google APIs for calendar/email features
**Critical Dependency:** Google outage = authentication outage (no mitigation currently)

---

## Deployment Details

### Domain & Hosting
- **Production:** sso.barge2rail.com
- **Platform:** Render PaaS
- **Database:** PostgreSQL (managed by Render)
- **SSL:** Auto-SSL via Render

### Environment Variables (Critical)
Set in Render dashboard:
```
BASE_URL=https://sso.barge2rail.com
GOOGLE_CLIENT_ID=[from Google Console]
GOOGLE_CLIENT_SECRET=[from Google Console]
SECRET_KEY=[Django secret for sessions/crypto]
DEBUG=False
ALLOWED_HOSTS=sso.barge2rail.com
DATABASE_URL=[provided by Render]
```

### OAuth Configuration
**Google Console Setup:**
- Authorized redirect URIs must include: `https://sso.barge2rail.com/auth/google/callback`
- Trailing slashes matter - must match exactly
- Use `google_redirect_uri()` helper to ensure consistency

---

## Lessons Learned

### October 4, 2025: God Mode Shell Fix
**What:** Fixed bash/zsh incompatibility in shell configuration
**Why:** Claude Code claimed "clean loading" but verbose output remained
**Lesson:** Always verify with functional tests, not just AI claims
**Impact:** Reinforced need for independent verification (code review before deployment)

### October 4, 2025: Safety System Validation
**What:** Proved three-perspective review catches AI oversights
**Why:** Single AI (Claude Code) missed edge case, second AI (The Bridge) caught it
**Lesson:** MEDIUM+ risk work requires multiple AI perspectives or human review
**Impact:** Established mandatory three-perspective review for all MEDIUM+ risk changes

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

## Working With This System

### When to Update This File
- Architecture decisions change (document why)
- New integration points added
- Lessons learned from production issues
- Deployment configuration changes

### Related Files
- **Shared Django patterns:** `../CLAUDE.md` (OAuth, sessions, Render deployment)
- **Universal patterns:** `../../CLAUDE.md` (security, ADHD-friendly, edge cases)

### Project Repository
Location: `/Users/cerion/Projects/barge2rail-auth`

---

## Patterns That Work Here

### Pattern 1: Long-Session Token Refresh
**Use Case:** User working for hours with intermittent activity
**Implementation:** 8-hour session timeout + refresh tokens + extend session on activity
**Rationale:** Logistics work is long-duration with interruptions

### Pattern 2: Mobile-First OAuth Flow
**Use Case:** Field technician logging in from phone in vehicle
**Implementation:** Large touch targets, minimal typing, clear success/failure states
**Rationale:** Mobile users often have gloves, poor connectivity, need clarity

### Pattern 3: Graceful Re-Authentication
**Use Case:** Token expires mid-session
**Implementation:** Clear message, preserve form state, easy return to work
**Rationale:** Don't punish users for interruptions - make recovery seamless

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Short Session Timeouts
**What:** 30-minute session timeout (Django default)
**Why Avoid:** Logistics work sessions last hours with interruptions
**Use Instead:** 8-hour timeout with refresh tokens

### Anti-Pattern 2: Technical Error Messages
**What:** "OAuthTokenRefreshException: invalid_grant"
**Why Avoid:** Non-technical users don't understand technical jargon
**Use Instead:** "Your session expired. Please log in again." [Login Button]

### Anti-Pattern 3: Assuming Continuous Network
**What:** No offline mode, no retry logic, immediate failure on network error
**Why Avoid:** Field technicians have spotty connectivity
**Use Instead:** Retry with exponential backoff, offline queue, clear status indicators

---

**Last Updated:** October 4, 2025 by The Bridge
