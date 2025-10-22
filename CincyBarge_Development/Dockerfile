# Use the official Python image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput || true

# Expose the port your app runs on
EXPOSE 8000

# Create entrypoint script with database wait
RUN echo '#!/bin/sh\n\
echo "Waiting for PostgreSQL..."\n\
while ! nc -z $DB_HOST $DB_PORT; do\n\
  sleep 0.1\n\
done\n\
echo "PostgreSQL started"\n\
python manage.py migrate --noinput\n\
python manage.py runserver 0.0.0.0:8000' > /entrypoint.sh && \
chmod +x /entrypoint.sh

# Install system dependencies for pdfplumber and netcat for database wait check
RUN apt-get update && \
    apt-get install -y \
    netcat-traditional \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Use the entrypoint script
ENTRYPOINT ["/entrypoint.sh"]
