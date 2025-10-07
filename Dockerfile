# Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create logs directory
RUN mkdir -p logs

# REMOVED: collectstatic (will run at startup instead)
# REMOVED: migrate (will run at startup instead)

# Expose port
EXPOSE 8000

# Create startup script that runs migrations, collectstatic, then starts server
RUN echo '#!/bin/bash\n\
set -e\n\
echo "Running migrations..."\n\
python manage.py migrate --noinput\n\
echo "Collecting static files..."\n\
python manage.py collectstatic --noinput\n\
echo "Starting server..."\n\
gunicorn core.wsgi:application --bind 0.0.0.0:8000 --workers 2 --threads 4 --timeout 60\n\
' > /app/start.sh && chmod +x /app/start.sh

# Use startup script as entrypoint
CMD ["/app/start.sh"]
