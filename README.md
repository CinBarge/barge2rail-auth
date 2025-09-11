# Barge2Rail SSO System

Centralized authentication system for all Barge2Rail applications.

## Features

- JWT-based authentication
- Admin dashboard for user management
- REST API for application integration
- Client JavaScript library
- Multi-application support with role-based access

## Quick Start

### Development Setup

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Run migrations:**
```bash
python manage.py migrate
```

3. **Create superuser:**
```bash
python manage.py create_test_superuser
# Creates admin@barge2rail.com with password: admin123
```

4. **Run development server:**
```bash
python manage.py runserver
```

Access the admin dashboard at: http://localhost:8000/

## API Endpoints

### Authentication

- `POST /api/auth/register/` - Register new user
- `POST /api/auth/login/` - Login with email/password
- `POST /api/auth/logout/` - Logout and blacklist token
- `POST /api/auth/refresh/` - Refresh access token
- `POST /api/auth/validate/` - Validate and decode token
- `GET /api/auth/profile/` - Get current user profile

### Application Management

- `GET /api/auth/applications/` - List applications
- `POST /api/auth/applications/` - Create application
- `GET /api/auth/applications/{id}/` - Get application details
- `PUT /api/auth/applications/{id}/` - Update application
- `DELETE /api/auth/applications/{id}/` - Delete application

### User Roles

- `GET /api/auth/roles/` - List user roles
- `POST /api/auth/roles/` - Create user role
- `GET /api/auth/roles/{id}/` - Get role details
- `PUT /api/auth/roles/{id}/` - Update role
- `DELETE /api/auth/roles/{id}/` - Delete role

## Client Integration

### JavaScript Library

Include the SSO client library in your application:

```html
<script src="https://sso.barge2rail.com/static/js/barge2rail-sso.js"></script>
```

### Basic Usage

```javascript
// Initialize with custom SSO URL
Barge2RailSSO.init({
    ssoUrl: 'https://sso.barge2rail.com'
});

// Login
await Barge2RailSSO.login('user@example.com', 'password');

// Check authentication
if (Barge2RailSSO.isAuthenticated()) {
    const user = Barge2RailSSO.getUser();
    console.log('Logged in as:', user.email);
}

// Make authenticated API request
const data = await Barge2RailSSO.authenticatedRequest('/api/your-endpoint/');

// Logout
await Barge2RailSSO.logout();
```

### Auto Token Refresh

```javascript
// Setup automatic token refresh
Barge2RailSSO.setupAutoRefresh();
```

## Environment Variables

Create a `.env` file with:

```env
SECRET_KEY=your-secret-key-here
DEBUG=False
ALLOWED_HOSTS=sso.barge2rail.com
DATABASE_URL=postgresql://user:pass@localhost/dbname
CORS_ALLOWED_ORIGINS=https://prt.barge2rail.com,https://app.barge2rail.com
```

## Production Deployment

1. **Set environment to production:**
```bash
export DEBUG=False
```

2. **Collect static files:**
```bash
python manage.py collectstatic
```

3. **Run with Gunicorn:**
```bash
gunicorn core.wsgi:application --bind 0.0.0.0:8000
```

## Security Notes

- Change `SECRET_KEY` in production
- Use HTTPS in production
- Configure CORS origins properly
- Set strong passwords for production users
- Enable CSRF protection for web forms
- Rotate JWT signing keys periodically

## Testing

Run tests:
```bash
python manage.py test
```

## License

Proprietary - Cincinnati Barge & Rail Terminal, LLC