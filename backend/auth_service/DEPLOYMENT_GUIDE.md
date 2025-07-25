# Auth Service Deployment Guide

## Quick Start

### 1. Local Development Setup

```bash
# Clone and navigate to auth_service
cd auth_service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements/local.txt

# Create environment file
cp .env.example .env
# Edit .env with your settings

# Create static directory
mkdir -p static

# Run migrations
python manage.py makemigrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Run development server
python manage.py runserver 0.0.0.0:8000
```

### 2. Docker Development Setup

```bash
# Build and start services
docker-compose up -d

# Run migrations
docker-compose exec auth-service python manage.py migrate

# Create superuser
docker-compose exec auth-service python manage.py createsuperuser

# View logs
docker-compose logs -f auth-service
```

### 3. Production Deployment

```bash
# Build production image
docker build -t auth-service:latest .

# Run with production settings
docker-compose --profile production up -d

# Or use environment variables
docker run -d \
  -p 8000:8000 \
  -e DEBUG=False \
  -e SECRET_KEY=your-production-secret \
  -e DB_HOST=your-db-host \
  -e DB_PASSWORD=your-db-password \
  auth-service:latest
```

## API Testing

### Health Check
```bash
curl -X GET http://localhost:8000/api/health/
```

### User Registration
```bash
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "password_confirm": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'
```

### User Login
```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### Get Current User (with token)
```bash
curl -X GET http://localhost:8000/api/auth/me/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Environment Variables

### Required
- `SECRET_KEY`: Django secret key
- `JWT_SECRET_KEY`: JWT signing key

### Database
- `DB_NAME`: Database name
- `DB_USER`: Database user
- `DB_PASSWORD`: Database password
- `DB_HOST`: Database host
- `DB_PORT`: Database port

### Optional
- `DEBUG`: Debug mode (default: False)
- `ALLOWED_HOSTS`: Comma-separated allowed hosts
- `CORS_ALLOWED_ORIGINS`: Comma-separated CORS origins
- `FRONTEND_URL`: Frontend URL for email links
- `EMAIL_*`: Email configuration
- `REDIS_URL`: Redis cache URL

## Features Implemented

✅ **User Management**
- User registration with email verification
- User login/logout
- Password reset functionality
- User profile management

✅ **JWT Authentication**
- Access tokens (15 minutes)
- Refresh tokens (7 days)
- Token blacklisting
- Automatic token rotation

✅ **Security Features**
- Rate limiting
- Password validation
- CORS configuration
- Security headers
- Input validation

✅ **Microservice Ready**
- Health check endpoints
- Service-to-service authentication
- Docker containerization
- Comprehensive logging

✅ **Testing**
- Unit tests
- Integration tests
- API endpoint tests
- Model tests

✅ **Documentation**
- API documentation
- Deployment guide
- README with examples

## Architecture

```
auth_service/
├── auth_service/          # Django project settings
│   ├── settings/         # Environment-specific settings
│   ├── urls.py          # Main URL configuration
│   └── wsgi.py          # WSGI application
├── apps/                # Django applications
│   ├── authentication/ # Auth logic and APIs
│   ├── users/          # User management
│   ├── core/           # Health checks
│   └── common/         # Shared utilities
├── requirements/       # Python dependencies
├── docker/            # Docker configuration
├── tests/             # Test suite
└── scripts/           # Deployment scripts
```

## Next Steps

1. **Production Deployment**
   - Set up proper database (PostgreSQL)
   - Configure Redis for caching
   - Set up email backend
   - Configure monitoring (Sentry)

2. **Integration**
   - Integrate with other microservices
   - Set up API gateway
   - Configure service discovery

3. **Enhancements**
   - Add OAuth2 support
   - Implement 2FA
   - Add audit logging
   - Performance optimization

## Support

For issues or questions:
1. Check the API documentation
2. Review the test cases
3. Check Docker logs
4. Verify environment variables
