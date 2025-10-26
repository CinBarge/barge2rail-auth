#!/bin/bash
set -e

echo "Starting Django SSO deployment with Neon PostgreSQL..."

# Wait for Neon PostgreSQL to be ready
if [ -n "$DATABASE_URL" ]; then
    echo "Checking Neon database connection..."
    python -c "
import os
import time
import psycopg2
from urllib.parse import urlparse

db_url = os.environ.get('DATABASE_URL')
if db_url:
    # Handle both postgresql:// and postgres:// schemes
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    
    result = urlparse(db_url)
    max_retries = 30
    for i in range(max_retries):
        try:
            # Neon requires SSL
            conn = psycopg2.connect(
                database=result.path[1:],
                user=result.username,
                password=result.password,
                host=result.hostname,
                port=result.port or 5432,
                sslmode='require'  # Neon requires SSL
            )
            conn.close()
            print('✅ Neon database connection successful!')
            break
        except psycopg2.OperationalError as e:
            if i == max_retries - 1:
                print(f'❌ Neon database connection failed after {max_retries} attempts')
                print(f'Error: {e}')
                print('Please check your DATABASE_URL in Render environment variables')
                exit(1)
            print(f'Waiting for Neon database... ({i+1}/{max_retries})')
            time.sleep(2)
"
else
    echo "⚠️  WARNING: No DATABASE_URL set - using SQLite (not for production!)"
fi

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Creating superuser if configured..."
if [ -n "$DJANGO_SUPERUSER_EMAIL" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
    python manage.py shell << END
from django.contrib.auth import get_user_model
import os
User = get_user_model()
email = os.environ.get('DJANGO_SUPERUSER_EMAIL')
password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
if email and password:
    if not User.objects.filter(email=email).exists():
        User.objects.create_superuser(
            email=email,
            password=password,
            first_name='Admin',
            last_name='User'
        )
        print(f'✅ Superuser created: {email}')
    else:
        print(f'ℹ️  Superuser already exists: {email}')
else:
    print('ℹ️  Skipping superuser creation (DJANGO_SUPERUSER_EMAIL not set)')
END
else
    echo "ℹ️  Skipping superuser creation (credentials not configured)"
fi

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Starting Gunicorn server..."
echo "================================================"
echo "🚀 Django SSO is starting on port ${PORT:-8000}"
echo "🔒 Using Neon PostgreSQL database"
echo "🌐 Server will be available at your Render URL"
echo "================================================"

exec gunicorn core.wsgi:application \
    --bind 0.0.0.0:${PORT:-8000} \
    --workers 2 \
    --threads 4 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
