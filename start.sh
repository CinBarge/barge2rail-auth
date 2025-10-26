#!/bin/bash
set -e

echo "Starting Django SSO deployment..."

# Wait for database to be ready (PostgreSQL specific)
if [ -n "$DATABASE_URL" ]; then
    echo "Waiting for database..."
    python -c "
import os
import time
import psycopg2
from urllib.parse import urlparse

db_url = os.environ.get('DATABASE_URL')
if db_url:
    result = urlparse(db_url)
    max_retries = 30
    for i in range(max_retries):
        try:
            conn = psycopg2.connect(
                database=result.path[1:],
                user=result.username,
                password=result.password,
                host=result.hostname,
                port=result.port
            )
            conn.close()
            print('Database is ready!')
            break
        except psycopg2.OperationalError:
            if i == max_retries - 1:
                print('Database connection failed after 30 attempts')
                exit(1)
            print(f'Database not ready, waiting... ({i+1}/{max_retries})')
            time.sleep(1)
"
fi

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Creating superuser if it doesn't exist..."
python manage.py shell << END
from django.contrib.auth import get_user_model
import os
User = get_user_model()
email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@barge2rail.com')
if not User.objects.filter(email=email).exists():
    User.objects.create_superuser(
        email=email,
        password=os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'ChangeMeImmediately!'),
        first_name='Admin',
        last_name='User'
    )
    print(f'Superuser created: {email}')
else:
    print(f'Superuser already exists: {email}')
END

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Starting Gunicorn server..."
exec gunicorn core.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 2 \
    --threads 4 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
