#!/bin/bash

# Auth Service Startup Script

set -e

echo "Starting Auth Service..."

# Wait for database to be ready
echo "Waiting for database..."
while ! python manage.py dbshell --command="SELECT 1;" > /dev/null 2>&1; do
    echo "Database is unavailable - sleeping"
    sleep 1
done
echo "Database is ready!"

# Run migrations
echo "Running database migrations..."
python manage.py migrate --noinput

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput

# Create superuser if it doesn't exist
echo "Creating superuser if needed..."
python manage.py shell << EOF
from django.contrib.auth import get_user_model
import os

User = get_user_model()

if not User.objects.filter(is_superuser=True).exists():
    email = os.environ.get('SUPERUSER_EMAIL', 'admin@example.com')
    password = os.environ.get('SUPERUSER_PASSWORD', 'admin123')
    
    User.objects.create_superuser(
        email=email,
        password=password
    )
    print(f"Superuser created: {email}")
else:
    print("Superuser already exists")
EOF

# Start the server
echo "Starting server..."
if [ "$DEBUG" = "True" ]; then
    echo "Running in development mode..."
    python manage.py runserver 0.0.0.0:8000
else
    echo "Running in production mode..."
    gunicorn auth_service.wsgi:application
fi
