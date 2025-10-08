# Barge2Rail SSO System - Project Index

**Status:** ✅ Live in Production  
**Production URL:** https://sso.barge2rail.com  
**Deployed:** October 7-8, 2025  
**Test Coverage:** 74% (40/40 tests passing)

---

## Overview

Barge2Rail SSO is a centralized Single Sign-On authentication system for all Barge2Rail applications. Built with Django and Django REST Framework, it provides JWT-based authentication with Google Workspace OAuth 2.0, comprehensive security features including rate limiting and account lockout, and support for multiple authentication methods.

**Key Achievement:** Successfully deployed using HIGH RISK protocol in 4 days (vs 3-4 month estimate), with zero security incidents on first deployment.

---

## Production Status

### Live Features
- ✅ Google Workspace OAuth 2.0 authentication
- ✅ JWT tokens with email claims
- ✅ Automatic token refresh
- ✅ Token blacklisting on logout
- ✅ Rate limiting (5/10/20/100 per hour)
- ✅ Account lockout after 5 failed attempts
- ✅ 12-digit anonymous user PINs
- ✅ OAuth state validation (60-second timeout)
- ✅ HTTPS with auto-SSL
- ✅ Health check monitoring

### Infrastructure
- **Platform:** Render PaaS (Docker)
- **Region:** Ohio (Columbus)
- **Domain:** sso.barge2rail.com (custom domain with SSL)
- **Database:** PostgreSQL (managed by Render)
- **Monitoring:** Health check at /api/auth/health/

---

## Architecture

### Technology Stack
- **Backend:** Django 4.2+ with Django REST Framework
- **Authentication:** JWT tokens via djangorestframework-simplejwt
- **OAuth:** Google Workspace OAuth 2.0
- **Database:** SQLite (development) / PostgreSQL (production)
- **Deployment:** Docker + Render PaaS
- **SSL:** Let's Encrypt (auto-renewal)
- **Security:** Rate limiting, CSRF protection, token blacklisting

### Key Components
- **sso/views.py** - Authentication endpoints and OAuth flow
- **sso/models.py** - User, TokenExchangeSession, LoginAttempt models
- **sso/tokens.py** - Custom JWT with email claims
- **sso/utils.py** - Rate limiting exception handler
- **sso/tests/** - Comprehensive test suite (40 tests across 5 files)

---

## 📁 Project Structure

```
barge2rail-auth/
├── 📄 Configuration Files
│   ├── .env                        # Environment variables (local dev)
│   ├── .env.example                # Environment variable template
│   ├── .gitignore                  # Git ignore patterns
│   ├── Dockerfile                  # Docker container configuration
│   ├── render.yaml                 # Render deployment configuration
│   ├── manage.py                   # Django management script
│   ├── requirements.txt            # Python dependencies
│   ├── run_tests.sh                # Test runner with coverage
│   └── db.sqlite3                  # SQLite database (development)
│
├── 📋 Documentation
│   ├── README.md                   # Quick start guide (UPDATED)
│   ├── INDEX.md                    # This file - comprehensive project index
│   ├── technical-handoff.md        # Complete deployment documentation
│   ├── claude.md                   # AI assistant context and patterns
│   ├── CONTRIBUTING.md             # Contribution guidelines
│   ├── FUNCTIONAL_TESTS.md         # Test specifications
│   ├── OAUTH_IMPLEMENTATION_COMPLETE.md  # OAuth implementation details
│   └── IMPLEMENTATION_STATUS.md    # Historical implementation status
│
├── 🎯 Core Application
│   └── core/                       # Django project settings
│       ├── __init__.py
│       ├── settings.py             # Main settings (UPDATED)
│       ├── urls.py                 # Root URL configuration
│       ├── wsgi.py                 # WSGI configuration
│       └── asgi.py                 # ASGI configuration
│
├── 🔐 SSO Application
│   └── sso/                        # Main authentication app
│       ├── migrations/             # Database migrations
│       │   ├── 0001_initial.py
│       │   ├── 0002_*.py
│       │   ├── 0003_applicationrole.py
│       │   ├── 0004_tokenexchangesession.py
│       │   └── 0005_loginattempt.py
│       ├── management/             # Management commands
│       │   └── commands/
│       │       ├── cleanup_old_login_attempts.py
│       │       ├── cleanup_token_sessions.py
│       │       └── create_test_superuser.py
│       ├── tests/                  # Test suite (NEW)
│       │   ├── __init__.py
│       │   ├── test_oauth_flow.py      # OAuth state, URL, callbacks (18 tests)
│       │   ├── test_token_management.py # Token lifecycle (8 tests)
│       │   ├── test_security.py        # Security features (9 tests)
│       │   ├── test_rate_limiting.py   # Rate limits (4 tests)
│       │   └── test_integration.py     # End-to-end flows (4 tests)
│       ├── __init__.py
│       ├── admin.py                # Admin panel configuration
│       ├── apps.py                 # App configuration
│       ├── models.py               # Data models
│       ├── serializers.py          # DRF serializers
│       ├── views.py                # API endpoints (UPDATED)
│       ├── urls.py                 # URL routing
│       ├── tokens.py               # Custom JWT (NEW)
│       └── utils.py                # Rate limiting handler (NEW)
│
└── 📦 Static & Templates
    ├── static/                     # Static files
    │   ├── css/
    │   ├── js/
    │   └── img/
    └── templates/                  # HTML templates
        └── sso/
```

---

## API Endpoints

### Authentication Endpoints
| Endpoint | Method | Purpose | Rate Limit |
|----------|--------|---------|------------|
| `/api/auth/login/google/` | GET | Initiate Google OAuth | 20/hour |
| `/auth/google/callback/` | GET | OAuth callback | - |
| `/api/auth/login/email/` | POST | Email/password login | 5/hour |
| `/api/auth/login/anonymous/` | POST | Anonymous user login | 10/hour |
| `/api/auth/logout/` | POST | Logout (blacklist tokens) | - |
| `/api/auth/refresh/` | POST | Refresh access token | - |
| `/api/auth/validate/` | POST | Validate access token | 100/hour |
| `/api/auth/session/{id}/tokens/` | GET | Exchange session for tokens | - |
| `/api/auth/health/` | GET | Health check | - |

---

## Security Features

### Authentication Security
- **OAuth State Parameter:** 60-second timeout with CSRF protection
- **Token Exchange:** Secure two-step pattern (no tokens in URLs)
- **Token Blacklisting:** Refresh tokens invalidated on logout
- **JWT Claims:** Include user email for convenience
- **Anonymous PINs:** 12-digit (not 6-digit) for security

### Rate Limiting & Protection
- **Email Login:** 5 attempts per hour per IP
- **Anonymous Login:** 10 attempts per hour per IP
- **OAuth Endpoint:** 20 attempts per hour per IP
- **Token Validation:** 100 requests per hour per IP
- **Account Lockout:** 5 failed attempts triggers lockout
- **Login Attempt Logging:** All attempts tracked with IP and timestamp

### Infrastructure Security
- **HTTPS Only:** Enforced via Let's Encrypt SSL
- **CSRF Protection:** Django CSRF middleware active
- **CORS Configuration:** Restricted to allowed origins
- **Secure Cookies:** httponly, secure, samesite settings
- **Environment Separation:** DEBUG=False in production

---

## Testing

### Test Suite
**Location:** `sso/tests/`  
**Total Tests:** 40  
**Pass Rate:** 100%  
**Coverage:** 74% overall (95% on models, 74% on views)

**Test Categories:**
1. **OAuth Flow (18 tests)** - State validation, URL generation, callbacks
2. **Token Management (8 tests)** - Generation, validation, refresh, blacklist
3. **Security (9 tests)** - Rate limiting, account lockout, CSRF, PINs
4. **Rate Limiting (4 tests)** - Configuration and endpoint limits
5. **Integration (4 tests)** - End-to-end authentication flows

**Run Tests:**
```bash
./run_tests.sh                           # All tests with coverage
python manage.py test sso.tests          # All tests
python manage.py test sso.tests.test_oauth_flow  # Specific test file
```

---

## Deployment

### Production Deployment (Render)
**Platform:** Render PaaS (Docker-based)  
**Region:** Ohio (Columbus)  
**Service:** barge2rail-sso  
**Custom Domain:** sso.barge2rail.com  
**SSL:** Auto-renewal via Let's Encrypt

**Deployment Process:**
1. Push to `main` branch on GitHub
2. Render automatically builds Docker image
3. Runs database migrations (`python manage.py migrate`)
4. Collects static files (`python manage.py collectstatic`)
5. Starts Gunicorn server with 2 workers, 4 threads
6. Health check verifies deployment

**Environment Variables:**
- BASE_URL, DEBUG, ALLOWED_HOSTS
- SECRET_KEY (unique to production)
- GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
- CSRF_TRUSTED_ORIGINS, CORS_ALLOWED_ORIGINS

### Local Development
```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with local settings

# Run
python manage.py migrate
python manage.py runserver

# Test
./run_tests.sh
```

---

## Integration Guide

### For Client Applications

**Step 1: Redirect to SSO**
```javascript
window.location.href = 'https://sso.barge2rail.com/api/auth/login/google/';
```

**Step 2: Handle Callback**
```javascript
// User returns to your app with session_id in URL
const urlParams = new URLSearchParams(window.location.search);
const sessionId = urlParams.get('session_id');
```

**Step 3: Exchange for Tokens**
```javascript
const response = await fetch(
  `https://sso.barge2rail.com/api/auth/session/${sessionId}/tokens/`
);
const { access, refresh, user } = await response.json();
```

**Step 4: Use Tokens**
```javascript
// Store tokens securely
localStorage.setItem('access_token', access);
localStorage.setItem('refresh_token', refresh);

// Use in API requests
fetch('https://your-app.com/api/endpoint', {
  headers: {
    'Authorization': `Bearer ${access}`
  }
});
```

**Step 5: Refresh When Expired**
```javascript
const response = await fetch('https://sso.barge2rail.com/api/auth/refresh/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ refresh: refresh_token })
});
const { access } = await response.json();
```

---

## Development Guidelines

### Code Standards
- Follow Django best practices
- Use type hints where appropriate
- Write tests for all new features
- Document complex logic
- Keep views focused and slim
- Use serializers for validation

### Security Requirements
- Never commit secrets to git
- Use environment variables for configuration
- Implement rate limiting on new endpoints
- Log security-relevant events
- Follow OWASP guidelines
- Test authentication flows thoroughly

### Testing Requirements
- 100% test pass rate before merge
- Minimum 70% code coverage
- All security features tested
- Integration tests for new flows
- Run full test suite before deployment

---

## Monitoring & Maintenance

### Health Monitoring
**Endpoint:** https://sso.barge2rail.com/api/auth/health/  
**Expected Response:** `{"status": "healthy"}`

### Logs
Access via Render Dashboard → Service → Logs

### Performance Metrics
- **Response Time:** < 2 seconds (target)
- **Uptime:** 99.9% (target)
- **Error Rate:** < 0.1% (target)

### Maintenance Tasks
**Daily (First 72 hours):**
- Check Render logs for errors
- Verify health check endpoint
- Monitor login success/failure rates

**Weekly:**
- Review LoginAttempt logs for suspicious activity
- Run cleanup commands (old attempts, expired sessions)
- Check SSL certificate status
- Review performance metrics

**Monthly:**
- Audit active users and access patterns
- Review and update dependencies
- Check for Django/DRF security updates
- Test rollback procedure
- Update documentation

---

## Troubleshooting

### Common Issues

**OAuth Redirect Mismatch:**
- Verify redirect URI in Google Console matches exactly
- Check BASE_URL environment variable
- Ensure HTTPS in production

**Rate Limit Errors:**
- Check LoginAttempt model for IP-based blocks
- Clear old attempts: `python manage.py cleanup_old_login_attempts`
- Verify RATELIMIT_ENABLE setting

**Token Issues:**
- Check token hasn't expired (default: 5 min access, 1 day refresh)
- Verify SECRET_KEY is consistent across deployments
- Check token_blacklist for revoked tokens

**Health Check Failing:**
- Check database connectivity
- Verify migrations are applied
- Check application logs in Render

---

## Project History

### Timeline
- **September 2025:** Initial development and OAuth implementation
- **October 4, 2025:** Risk assessment (HIGH RISK - 53/60)
- **October 4, 2025:** Three-perspective security review (17 issues found)
- **October 7, 2025:** Test suite implementation (40 tests)
- **October 7, 2025:** All security issues resolved
- **October 7-8, 2025:** Production deployment completed
- **October 8, 2025:** OAuth verified working in production

### Key Achievements
- ✅ Deployed using HIGH RISK protocol successfully
- ✅ Zero security incidents on first deployment
- ✅ All 40 tests passing (100% pass rate)
- ✅ Completed in 4 days vs 3-4 month estimate (20x efficiency)
- ✅ Framework validation: Three-perspective review caught 17 issues

---

## Documentation

### Primary Documentation
- **README.md** - Quick start and overview
- **technical-handoff.md** - Complete deployment documentation and status
- **claude.md** - AI assistant context, patterns, and project knowledge
- **CONTRIBUTING.md** - Contribution guidelines and standards

### Technical Documentation
- **FUNCTIONAL_TESTS.md** - Test specifications
- **OAUTH_IMPLEMENTATION_COMPLETE.md** - OAuth implementation details
- **IMPLEMENTATION_STATUS.md** - Historical implementation status

### Development Documentation
- **WARP.md** - AI assistant guidelines
- **CLAUDE_CODE_HANDOFF.md** - Claude Code integration guide
- **galactica-integration.md** - Memory system integration

---

## Support & Resources

**Production Status:** https://sso.barge2rail.com/api/auth/health/  
**Repository:** https://github.com/CinBarge/barge2rail-auth  
**Issues:** Report via GitHub Issues  
**Render Dashboard:** https://dashboard.render.com

**Health Check:**
```bash
curl https://sso.barge2rail.com/api/auth/health/
```

**Test Locally:**
```bash
cd /Users/cerion/Projects/barge2rail-auth
./run_tests.sh
```

---

## License

Proprietary - Barge2Rail Internal Use Only

---

*Last updated: October 8, 2025 - Production deployment successful*