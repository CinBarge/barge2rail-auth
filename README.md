# Barge2Rail SSO System

**Status:** ✅ Live in Production  
**Production URL:** https://sso.barge2rail.com  
**Deployed:** October 7-8, 2025

Centralized authentication system for all Barge2Rail applications using Google Workspace OAuth 2.0.

---

## Production Features

### Authentication
- ✅ Google Workspace OAuth 2.0 integration
- ✅ JWT-based tokens with email claims
- ✅ Automatic token refresh
- ✅ Secure token blacklisting on logout
- ✅ Anonymous user support (12-digit PINs)

### Security
- ✅ Rate limiting (5/10/20/100 requests per hour by endpoint)
- ✅ Account lockout after 5 failed attempts
- ✅ OAuth state parameter with 60-second timeout
- ✅ CSRF protection
- ✅ HTTPS with auto-SSL (Let's Encrypt)
- ✅ Secure two-step token exchange

### Infrastructure
- ✅ Docker containerized deployment
- ✅ Render PaaS hosting
- ✅ Custom domain with SSL
- ✅ Health check monitoring
- ✅ Automated migrations on deploy

---

## API Endpoints

### Authentication
- `GET /api/auth/login/google/` - Initiate Google OAuth flow
- `GET /auth/google/callback/` - OAuth callback (handles redirect)
- `POST /api/auth/login/email/` - Email/password authentication
- `POST /api/auth/login/anonymous/` - Anonymous user login
- `POST /api/auth/logout/` - Logout (blacklist tokens)

### Token Management
- `POST /api/auth/refresh/` - Refresh access token
- `POST /api/auth/validate/` - Validate access token
- `GET /api/auth/session/{session_id}/tokens/` - Exchange session for tokens

### Monitoring
- `GET /api/auth/health/` - Health check endpoint

---

## Quick Start

### Local Development Setup

1. **Clone repository:**
```bash
git clone https://github.com/CinBarge/barge2rail-auth.git
cd barge2rail-auth
```

2. **Create virtual environment:**
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your local development settings
```

5. **Run migrations:**
```bash
python manage.py migrate
```

6. **Create superuser:**
```bash
python manage.py createsuperuser
```

7. **Run development server:**
```bash
python manage.py runserver
```

8. **Access local instance:**
- Application: http://127.0.0.1:8000
- Admin panel: http://127.0.0.1:8000/admin
- API docs: http://127.0.0.1:8000/api/

---

## Testing

### Run Test Suite
```bash
# Run all tests with coverage
./run_tests.sh

# Run specific test file
python manage.py test sso.tests.test_oauth_flow

# Run with verbose output
python manage.py test --verbosity=2
```

**Test Coverage:** 74% overall
- 40 tests total
- 100% pass rate in production

---

## Deployment

### Production Deployment (Render)

**Platform:** Render PaaS (Docker)  
**Region:** Ohio (Columbus)  
**Domain:** sso.barge2rail.com

The application deploys automatically via Dockerfile:
1. Runs database migrations
2. Collects static files
3. Starts Gunicorn server

### Environment Variables (Production)
```
BASE_URL=https://sso.barge2rail.com
DEBUG=False
ALLOWED_HOSTS=sso.barge2rail.com,barge2rail-sso.onrender.com
SECRET_KEY=<production-secret>
GOOGLE_CLIENT_ID=<production-client-id>
GOOGLE_CLIENT_SECRET=<production-secret>
CSRF_TRUSTED_ORIGINS=https://sso.barge2rail.com
CORS_ALLOWED_ORIGINS=https://sso.barge2rail.com
```

---

## Architecture

### Technology Stack
- **Framework:** Django 4.2 + Django REST Framework
- **Authentication:** Google Workspace OAuth 2.0
- **Tokens:** JWT (djangorestframework-simplejwt)
- **Database:** SQLite (dev) / PostgreSQL (production)
- **Deployment:** Docker + Render PaaS
- **SSL:** Let's Encrypt (auto-renewal)

### Key Components
- `sso/views.py` - Authentication endpoints
- `sso/models.py` - User, TokenExchangeSession, LoginAttempt
- `sso/tokens.py` - Custom JWT with email claims
- `sso/utils.py` - Rate limiting exception handler
- `sso/tests/` - Comprehensive test suite (40 tests)

---

## Security

### HIGH RISK Protocol Applied
This system was deployed using The Bridge HIGH RISK deployment protocol:
- ✅ Three-perspective security review (17 issues identified and resolved)
- ✅ Comprehensive functional testing (40 tests, 100% pass rate)
- ✅ Independent code review
- ✅ Risk assessment (53/60 - HIGH RISK)
- ✅ Zero security incidents on first deployment

### Security Features
- OAuth state parameter validation (60-second timeout)
- Rate limiting on all authentication endpoints
- Account lockout after 5 failed attempts
- Token blacklisting on logout
- 12-digit PINs for anonymous users
- CSRF protection
- Secure cookie settings

---

## Integration

### For Client Applications

**OAuth Flow:**
```javascript
// 1. Redirect user to SSO
window.location.href = 'https://sso.barge2rail.com/api/auth/login/google/';

// 2. User authenticates with Google

// 3. SSO redirects back with session ID
// Extract session_id from redirect URL

// 4. Exchange session for tokens
const response = await fetch(`https://sso.barge2rail.com/api/auth/session/${sessionId}/tokens/`, {
  method: 'GET'
});
const { access, refresh, user } = await response.json();

// 5. Store tokens securely
localStorage.setItem('access_token', access);
localStorage.setItem('refresh_token', refresh);

// 6. Use access token for API requests
fetch('https://your-app.com/api/endpoint', {
  headers: {
    'Authorization': `Bearer ${access_token}`
  }
});
```

---

## Monitoring

### Health Check
```bash
curl https://sso.barge2rail.com/api/auth/health/
```

### Logs
View logs in Render dashboard: Settings → Logs

### Metrics
- Response time: < 2 seconds
- Uptime: 99.9% target
- Test coverage: 74%

---

## Documentation

- **technical-handoff.md** - Complete deployment documentation
- **claude.md** - AI assistant context and patterns
- **CONTRIBUTING.md** - Contribution guidelines
- **FUNCTIONAL_TESTS.md** - Test specifications

---

## Support

**Repository:** https://github.com/CinBarge/barge2rail-auth  
**Issues:** Report via GitHub Issues  
**Production Status:** https://sso.barge2rail.com/api/auth/health/

---

## License

Proprietary - Barge2Rail Internal Use Only

---

*Last updated: October 8, 2025*
