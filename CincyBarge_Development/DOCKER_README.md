# Docker Setup for CincyBarge2Rail

This document explains how to run the CincyBarge2Rail Django project using Docker.

## Prerequisites

- Docker installed on your system
- Docker Compose installed (usually comes with Docker Desktop)

## Quick Start

### Using Docker Compose (Recommended)

1. **Build and run the container:**
   ```bash
   docker-compose up --build
   ```

2. **Access the application:**
   - Open your browser and navigate to: `http://localhost:8000`

3. **Stop the container:**
   - Press `Ctrl+C` in the terminal
   - Or run: `docker-compose down`

### Using Docker directly

1. **Build the Docker image:**
   ```bash
   docker build -t cincybarge2rail .
   ```

2. **Run the container:**
   ```bash
   docker run -p 8000:8000 cincybarge2rail
   ```

3. **Access the application:**
   - Open your browser and navigate to: `http://localhost:8000`

## Common Docker Commands

### View running containers:
```bash
docker ps
```

### View all containers (including stopped):
```bash
docker ps -a
```

### Stop a running container:
```bash
docker stop <container_id>
```

### Remove a container:
```bash
docker rm <container_id>
```

### Remove the image:
```bash
docker rmi cincybarge2rail
```

### View logs:
```bash
docker-compose logs -f
```

## Important Notes

1. **Database:** The project now uses PostgreSQL running in a separate Docker container. Data is persisted in a Docker volume named `postgres_data`. Database credentials are:
   - Database: cincybarge2rail
   - User: postgres
   - Password: postgres
   - Host: db (internal Docker network)
   - Port: 5432

2. **Static Files:** Static files are collected automatically during the Docker build process.

3. **Hot Reload:** When using `docker-compose up`, the code is mounted as a volume, so changes to your code will be reflected immediately without rebuilding.

4. **Port Conflicts:** If port 8000 is already in use, modify the port mapping in `docker-compose.yml`:
   ```yaml
   ports:
     - "8080:8000"  # Maps host port 8080 to container port 8000
   ```

5. **Database Migrations:** Migrations run automatically when the container starts. The container waits for PostgreSQL to be ready before running migrations.

6. **Data Persistence:** PostgreSQL data is stored in a Docker volume. To reset the database, run:
   ```bash
   docker-compose down -v
   ```
   Note: This will delete all data!

## Troubleshooting

### Container fails to start
- Check logs: `docker-compose logs`
- Ensure port 8000 is not in use by another application
- Try rebuilding: `docker-compose up --build`

### Changes not reflected
- Rebuild the image: `docker-compose up --build`
- Clear Docker cache: `docker-compose build --no-cache`

### Permission issues
- On Linux/Mac, you may need to adjust file permissions
- Run Docker commands with appropriate permissions

## Production Considerations

For production deployment, consider:
1. Setting `DEBUG = False` in settings.py
2. Using environment variables for sensitive data
3. Using a production-grade database (PostgreSQL)
4. Using Gunicorn instead of Django's development server
5. Setting up proper ALLOWED_HOSTS
6. Using nginx as a reverse proxy
