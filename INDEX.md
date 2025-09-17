# Barge2Rail SSO System - Project Index

## Overview
Barge2Rail SSO is a centralized Single Sign-On authentication system for all Barge2Rail applications. Built with Django and Django REST Framework, it provides JWT-based authentication, multi-application support, role-based access control, and multiple authentication methods including Google OAuth, email/password, and anonymous PIN access.

## Architecture
- **Backend**: Django 4.2+ with Django REST Framework
- **Authentication**: JWT tokens via Simple JWT
- **Database**: SQLite (development) / PostgreSQL (production)
- **Frontend**: Static templates with vanilla JavaScript
- **OAuth Integration**: Google Sign-In support
- **Security**: CORS, CSRF protection, secure token management

## 📁 Project Structure

```
barge2rail-auth/
├── 📄 Configuration Files
│   ├── .env                        # Environment variables (secrets)
│   ├── .gitignore                  # Git ignore patterns
│   ├── manage.py                   # Django management script
│   ├── requirements.txt            # Python dependencies
│   ├── db.sqlite3                  # SQLite database (development)
│   └── *.pid/.log                  # Runtime files
│
├── 📋 Documentation
│   ├── README.md                   # Quick start guide
│   ├── INDEX.md                    # This file - comprehensive project index
│   ├── IMPLEMENTATION_STATUS.md    # Google OAuth implementation status
│   └── WARP.md                     # AI assistant guidelines
│
├── 🔧 Core Django Application
│   └── core/
│       ├── __init__.py
│       ├── settings.py             # Django configuration
│       ├── urls.py                 # Main URL routing
│       ├── wsgi.py                 # WSGI application
│       └── asgi.py                 # ASGI application
│
├── 🔐 SSO Authentication App
│   └── sso/
│       ├── models.py               # User, Application, UserRole models
│       ├── views.py                # REST API views
│       ├── auth_views.py           # Google OAuth specific views
│       ├── serializers.py          # API serializers
│       ├── urls.py                 # SSO API endpoints
│       ├── admin.py                # Django admin configuration
│       ├── apps.py                 # App configuration
│       ├── tests.py                # Unit tests
│       ├── migrations/             # Database migrations
│       └── management/             # Custom management commands
│
├── 📊 Dashboard Application
│   └── dashboard/
│       ├── views.py                # Dashboard and login views
│       ├── urls.py                 # Dashboard routing
│       ├── models.py               # Dashboard-specific models
│       ├── admin.py                # Admin interface
│       ├── apps.py                 # App configuration
│       ├── tests.py                # Dashboard tests
│       └── migrations/             # Database migrations
│
├── 🌐 Frontend Templates
│   └── templates/
│       ├── base.html               # Base template
│       ├── login.html              # Main login interface
│       └── dashboard/
│           ├── dashboard.html      # Admin dashboard
│           ├── enhanced_login.html # Enhanced login form
│           ├── google_onetap.html  # Google One-Tap login
│           └── simple_test.html    # Testing interface
│
├── 📦 Static Assets
│   ├── static/js/
│   │   ├── barge2rail-sso.js       # Client-side SSO library
│   │   └── barge2rail-sso-v2.js    # Updated SSO library
│   └── staticfiles/                # Collected static files
│
├── 🧪 Development & Testing Tools
│   ├── debug_*.sh                  # Debugging utilities
│   ├── diagnose_*.py              # Diagnostic scripts
│   ├── fix_*.sh                   # Issue resolution scripts
│   ├── setup_google_oauth.sh      # OAuth setup automation
│   ├── start_django_server.sh     # Server startup script
│   ├── test_*.sh/.html            # Testing tools and interfaces
│   └── verify_implementation.sh   # Implementation verification
│
└── 🐍 Python Environment
    └── venv/                       # Virtual environment
```

## 🚀 Quick Start

### Development Setup
```bash
# Clone repository
cd /Users/cerion/projects/barge2rail-auth

# Install dependencies
pip install -r requirements.txt

# Run database migrations
python manage.py migrate

# Create superuser
python manage.py create_test_superuser
# Creates admin@barge2rail.com with password: admin123

# Start development server
python manage.py runserver

# Access admin dashboard
open http://localhost:8000/
```

### Production Deployment
```bash
# Set production environment
export DEBUG=False

# Collect static files
python manage.py collectstatic

# Run with Gunicorn
gunicorn core.wsgi:application --bind 0.0.0.0:8000
```

## 🔑 Authentication Methods

### 1. **Email/Password Authentication**
- Standard Django user authentication
- Secure password validation
- JWT token issuance upon successful login

### 2. **Google OAuth Integration** ✅ COMPLETE
- **Client ID**: `<GOOGLE_CLIENT_ID>`
- **Redirect URIs**: Configured for local and production environments
- **Implementation**: Fully functional OAuth 2.0 flow
- **Features**: Token exchange, user creation/update, secure verification

### 3. **Anonymous PIN Access**
- Guest access with generated PIN codes
- Auto-generated usernames (e.g., `Guest-ABC123`)
- Temporary access for testing and demos

## 📡 API Endpoints

### Authentication Endpoints
```
POST /api/auth/register/          # Register new user
POST /api/auth/login/             # Email/password login
POST /api/auth/logout/            # Logout and blacklist token
POST /api/auth/refresh/           # Refresh access token
POST /api/auth/validate/          # Validate and decode token
GET  /api/auth/profile/           # Get current user profile
```

### Google OAuth Endpoints
```
GET  /api/auth/oauth/google/url/  # Get OAuth authorization URL
POST /api/auth/login/google/      # Handle Google OAuth login
GET  /api/auth/google/callback/   # OAuth callback handler
GET  /api/auth/config/google/     # Google configuration check
```

### Application Management
```
GET    /api/auth/applications/       # List applications
POST   /api/auth/applications/       # Create application
GET    /api/auth/applications/{id}/  # Get application details
PUT    /api/auth/applications/{id}/  # Update application
DELETE /api/auth/applications/{id}/  # Delete application
```

### User Role Management
```
GET    /api/auth/roles/       # List user roles
POST   /api/auth/roles/       # Create user role
GET    /api/auth/roles/{id}/  # Get role details
PUT    /api/auth/roles/{id}/  # Update role
DELETE /api/auth/roles/{id}/  # Delete role
```

## 🗃️ Data Models

### User Model
- **Fields**: UUID, email, phone, display_name, auth_type, google_id
- **Anonymous Support**: anonymous_username, pin_code, is_anonymous
- **Authentication**: Supports email, Google, and anonymous auth types
- **Security**: Secure PIN generation and username creation

### Application Model
- **Purpose**: Multi-tenant application registration
- **Fields**: name, slug, client_id, client_secret, redirect_uris
- **Features**: Client credential management, URI validation

### UserRole Model
- **Purpose**: Role-based access control
- **Roles**: admin, manager, user, viewer
- **Features**: Application-specific permissions, JSON permission storage

### RefreshToken Model
- **Purpose**: JWT refresh token management
- **Features**: Token rotation, expiration tracking, application binding

## 🔐 Security Features

### JWT Configuration
- **Access Token Lifetime**: 15 minutes
- **Refresh Token Lifetime**: 7 days
- **Token Rotation**: Enabled with blacklisting
- **Algorithm**: HS256 with Django SECRET_KEY

### OAuth Security
- **Token Verification**: Google ID token validation
- **Secure Exchange**: Authorization code to token exchange
- **User Matching**: Google ID linking and user creation
- **Redirect Validation**: Authorized redirect URI checking

### General Security
- **CORS**: Configured allowed origins
- **CSRF**: Protection enabled for web forms
- **HTTPS**: Required in production
- **Headers**: XSS, content-type sniffing protection

## 🧩 Client Integration

### JavaScript Library
Include the SSO client library in your application:
```html
<script src="https://sso.barge2rail.com/static/js/barge2rail-sso.js"></script>
```

### Basic Usage
```javascript
// Initialize SSO client
Barge2RailSSO.init({
    ssoUrl: 'https://sso.barge2rail.com'
});

// Login with email/password
await Barge2RailSSO.login('user@example.com', 'password');

// Login with Google
await Barge2RailSSO.loginWithGoogle();

// Check authentication status
if (Barge2RailSSO.isAuthenticated()) {
    const user = Barge2RailSSO.getUser();
    console.log('Logged in as:', user.email);
}

// Make authenticated requests
const data = await Barge2RailSSO.authenticatedRequest('/api/your-endpoint/');

// Logout
await Barge2RailSSO.logout();
```

### Auto Token Refresh
```javascript
// Setup automatic token refresh
Barge2RailSSO.setupAutoRefresh();
```

## 🧪 Testing & Debugging

### Automated Testing Scripts
```bash
# Comprehensive implementation verification
./verify_implementation.sh

# Test Google OAuth specifically
./test_implementation.sh

# Debug API endpoints
./debug_api_endpoints.sh

# Test Google authentication flow
./test_google_oauth.sh
```

### Manual Testing
```bash
# Check Google OAuth configuration
curl http://127.0.0.1:8000/api/auth/config/google/

# Get OAuth authorization URL
curl http://127.0.0.1:8000/api/auth/oauth/google/url/

# Health check
curl http://127.0.0.1:8000/api/auth/health/
```

### Browser Testing
1. Navigate to: `http://127.0.0.1:8000/login/`
2. Test all three authentication methods:
   - **Email Tab**: Standard login
   - **Google Tab**: OAuth flow
   - **Quick Access Tab**: Anonymous PIN access

## 📊 Implementation Status

### ✅ Completed Features
- ✅ **Django Backend**: Complete REST API implementation
- ✅ **Google OAuth**: Full OAuth 2.0 integration with token management
- ✅ **Multi-Auth Support**: Email, Google, and anonymous authentication
- ✅ **JWT Security**: Token-based authentication with refresh capability
- ✅ **Admin Dashboard**: User and application management interface
- ✅ **Client Library**: JavaScript SSO integration library
- ✅ **Testing Tools**: Comprehensive testing and debugging utilities

### 🔄 Current Capabilities
- **Multi-tenant**: Support for multiple applications
- **Role-based Access**: User role management per application
- **Security**: CORS, CSRF, secure token handling
- **Development**: Local emulation and testing environment

### 📝 Future Enhancements
- **SAML Integration**: Enterprise SSO protocols
- **2FA Support**: Multi-factor authentication
- **Audit Logging**: Comprehensive security logging
- **Mobile SDK**: Native mobile app integration
- **LDAP Integration**: Enterprise directory services

## 🛠️ Development Environment

### Dependencies
```python
Django>=4.2,<5.0                    # Web framework
djangorestframework                  # REST API framework  
djangorestframework-simplejwt        # JWT authentication
django-cors-headers                  # CORS support
python-decouple                      # Environment configuration
gunicorn                             # Production server
whitenoise                           # Static file serving
dj-database-url                      # Database URL parsing
google-auth==2.23.0                  # Google authentication
google-auth-oauthlib==1.0.0         # OAuth library
google-auth-httplib2==0.1.0         # HTTP client for Google Auth
```

### Environment Configuration
```bash
# Required environment variables
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=sso.barge2rail.com
DATABASE_URL=postgresql://user:pass@localhost/dbname
CORS_ALLOWED_ORIGINS=https://prt.barge2rail.com,https://app.barge2rail.com
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
BASE_URL=<BASE_URL>
```

## 🤝 Development Workflow

### Code Organization
- **Core**: Django project configuration and routing
- **SSO App**: Authentication logic and API endpoints
- **Dashboard App**: Administrative interface and views
- **Templates**: Frontend interfaces and login forms
- **Static**: Client-side JavaScript libraries and assets

### Testing Strategy
- **Unit Tests**: Model and view testing
- **Integration Tests**: End-to-end OAuth flow testing
- **API Tests**: REST endpoint validation
- **Browser Tests**: Frontend interface verification

### Debugging Tools
- **Diagnostic Scripts**: OAuth configuration verification
- **Log Analysis**: Django logging for troubleshooting
- **Test Interfaces**: HTML pages for manual testing
- **Shell Scripts**: Automated testing and setup

---

*Last updated: September 16, 2025*
*Project: Barge2Rail SSO Authentication System*
*Architecture: Django REST Framework with JWT Authentication*
*Status: Production Ready with Google OAuth Integration*