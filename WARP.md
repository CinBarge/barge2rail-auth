# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

This is the **Barge2Rail SSO System**, a centralized authentication service built with Django. It provides JWT-based authentication, multi-application support, and supports three authentication methods:

- Traditional email/password
- Google Sign-In integration  
- Anonymous user authentication with PIN codes

## Common Development Commands

### Environment Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# Create test superuser (admin@barge2rail.com / admin123)
python manage.py create_test_superuser
```

### Development Server
```bash
# Start development server
python manage.py runserver

# Start server on specific host/port
python manage.py runserver 127.0.0.1:8000
```

### Testing & Diagnostics
```bash
# Run all tests
python manage.py test

# Run tests for specific app
python manage.py test sso
python manage.py test dashboard

# Start Google Auth diagnostic tool
./test_google_auth.sh
```

### Database Management
```bash
# Create new migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate

# Reset database (development only)
rm db.sqlite3 && python manage.py migrate
```

### Production Deployment
```bash
# Collect static files
python manage.py collectstatic

# Run with Gunicorn
gunicorn core.wsgi:application --bind 0.0.0.0:8000
```

## Architecture Overview

### Core Structure
- **`core/`** - Django project configuration, main settings and URL routing
- **`sso/`** - Authentication app containing models, API views, and authentication logic
- **`dashboard/`** - Web dashboard for admin interface and diagnostic tools
- **`templates/`** - HTML templates for web interface and diagnostic pages
- **`static/`** - JavaScript client libraries for SSO integration

### Authentication Flow
The system uses JWT tokens with djangorestframework-simplejwt. Custom authentication views in `sso/auth_views.py` handle three auth types:
- `login_email()` - Traditional username/password
- `login_google()` - Google OAuth verification with google-auth library
- `login_anonymous()` - Anonymous users with generated username/PIN

### Data Models
- **`User`** - Extended AbstractUser with UUID primary key, supports multiple auth types
- **`Application`** - Client applications that integrate with the SSO system
- **`UserRole`** - Role-based access control per application
- **`RefreshToken`** - JWT refresh token management

### API Structure
All authentication endpoints are under `/api/auth/`:
- Enhanced auth: `/api/auth/login/email/`, `/api/auth/login/google/`, `/api/auth/login/anonymous/`
- Legacy endpoints: `/api/auth/login/`, `/api/auth/register/`, `/api/auth/logout/`
- Management: `/api/auth/applications/`, `/api/auth/roles/`

### Diagnostic Tools
The system includes comprehensive Google Auth diagnostic tools accessible at:
- `/login/google-diagnostic/` - Full diagnostic interface
- `/login/google-test/` - Basic Google Sign-In test
- `/login/google-onetap/` - Google One Tap test

## Environment Configuration

### Required Environment Variables
```env
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=sso.barge2rail.com
DATABASE_URL=postgresql://user:pass@localhost/dbname
CORS_ALLOWED_ORIGINS=https://prt.barge2rail.com,https://app.barge2rail.com
GOOGLE_CLIENT_ID=your-google-client-id
```

### JWT Configuration
- Access tokens expire in 15 minutes
- Refresh tokens expire in 7 days with rotation
- Custom claims include user roles, auth type, and admin status

### CORS & Security
- Configured for cross-origin requests from client applications
- CSRF protection enabled for web forms
- XSS and content-type sniffing protection
- SSL redirect and secure cookies in production

## Client Integration

### JavaScript Library
The system provides `barge2rail-sso.js` and `barge2rail-sso-v2.js` client libraries for easy integration. Key methods:
- `Barge2RailSSO.init()` - Initialize with SSO URL
- `Barge2RailSSO.login()` - Authenticate user
- `Barge2RailSSO.isAuthenticated()` - Check auth status
- `Barge2RailSSO.authenticatedRequest()` - Make authenticated API calls

### Multi-Application Architecture
Each client application registers with the SSO system and receives:
- Unique client ID and secret
- Role-based permissions per user
- JWT tokens with application-specific claims

## Google Authentication Setup

### Dependencies
Requires `google-auth`, `google-auth-oauthlib`, and `google-auth-httplib2` packages.

### Common Issues
- **Popup blocking**: The diagnostic tool detects popup blockers that prevent Google Sign-In
- **Client ID configuration**: Ensure `GOOGLE_CLIENT_ID` environment variable is set
- **CORS issues**: Google Sign-In requires proper origin configuration

### Diagnostic Features
The `/login/google-diagnostic/` endpoint provides:
- Browser compatibility check
- Popup blocking detection  
- Protocol and security verification
- Google Sign-In library loading status

## Development Patterns

### Custom User Model
Uses UUID primary keys and supports multiple authentication types. Anonymous users get auto-generated usernames (Guest-ABC123) and 6-digit PIN codes.

### Error Handling
Authentication views return consistent JSON error responses with appropriate HTTP status codes.

### Database Design  
All models use UUID primary keys for security. Custom `db_table` names follow `sso_*` pattern for clear organization.
