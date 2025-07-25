# Auth Service

A comprehensive authentication microservice built with Django REST Framework, designed for microservice architecture.

## Features

- **User Management**: Registration, login, profile management
- **JWT Authentication**: Access and refresh tokens with blacklisting
- **Google OAuth**: Social login with Google accounts
- **Email Verification**: Email verification for new accounts
- **Password Reset**: Secure password reset functionality
- **Role-based Access Control**: Admin and user roles
- **Rate Limiting**: Protection against brute force attacks
- **Health Checks**: Service monitoring endpoints
- **Docker Support**: Containerized deployment
- **Comprehensive Testing**: Unit and integration tests

## Quick Start

### Using Docker (Recommended)

1. Clone the repository:
```bash
git clone <repository-url>
cd auth_service
```

2. Copy environment file:
```bash
cp .env.example .env
```

3. Update environment variables in `.env` file

4. Start services:
```bash
docker-compose up -d
```

5. Run migrations:
```bash
docker-compose exec auth-service python manage.py migrate
```

6. Create superuser:
```bash
docker-compose exec auth-service python manage.py createsuperuser
```

### Local Development

1. Create virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements/local.txt
```

3. Set up environment:
```bash
cp .env.example .env
# Update .env with your settings
```

4. Run migrations:
```bash
python manage.py migrate
```

5. Start development server:
```bash
python manage.py runserver
```

## API Endpoints

### Authentication

- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/logout/` - User logout
- `POST /api/auth/refresh/` - Refresh access token
- `GET /api/auth/me/` - Get current user info
- `PUT /api/auth/me/` - Update current user info

### Password Management

- `POST /api/auth/password/reset/request/` - Request password reset
- `POST /api/auth/password/reset/` - Reset password with token
- `POST /api/auth/password/change/` - Change password (authenticated)

### Email Verification

- `POST /api/auth/email/verify/` - Verify email with token
- `POST /api/auth/email/resend/` - Resend verification email

### User Management

- `GET /api/users/` - List users (admin only)
- `GET /api/users/{id}/` - Get user details
- `PUT /api/users/{id}/` - Update user
- `GET /api/users/{id}/profile/` - Get user profile
- `PUT /api/users/{id}/profile/` - Update user profile

### Health Check

- `GET /api/health/` - Service health status

## Authentication

The service uses JWT (JSON Web Tokens) for authentication:

1. **Access Token**: Short-lived token (15 minutes) for API access
2. **Refresh Token**: Long-lived token (7 days) for obtaining new access tokens

### Usage Example

```bash
# Register
curl -X POST http://localhost:8000/api/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123",
    "password_confirm": "securepassword123",
    "first_name": "John",
    "last_name": "Doe"
  }'

# Login
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'

# Google OAuth - Get auth URL
curl -X POST http://localhost:8000/api/auth/google/url/ \
  -H "Content-Type: application/json" \
  -d '{"state": "optional_state"}'

# Google OAuth - Login with code
curl -X POST http://localhost:8000/api/auth/google/callback/ \
  -H "Content-Type: application/json" \
  -d '{
    "code": "GOOGLE_AUTH_CODE",
    "state": "optional_state"
  }'

# Use access token
curl -X GET http://localhost:8000/api/auth/me/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

## Configuration

### Environment Variables

Key environment variables (see `.env.example` for full list):

- `SECRET_KEY`: Django secret key
- `DEBUG`: Debug mode (True/False)
- `DB_*`: Database configuration
- `JWT_SECRET_KEY`: JWT signing key
- `REDIS_URL`: Redis cache URL
- `EMAIL_*`: Email configuration
- `CORS_ALLOWED_ORIGINS`: Allowed CORS origins

### JWT Settings

Configure JWT behavior in `auth_service/settings/jwt.py`:

- `JWT_ACCESS_TOKEN_LIFETIME`: Access token lifetime
- `JWT_REFRESH_TOKEN_LIFETIME`: Refresh token lifetime
- `ROTATE_REFRESH_TOKENS`: Whether to rotate refresh tokens
- `BLACKLIST_AFTER_ROTATION`: Blacklist old refresh tokens

## Testing

Run tests with pytest:

```bash
# All tests
pytest

# With coverage
pytest --cov=apps

# Specific test file
pytest tests/test_authentication.py

# With Docker
docker-compose exec auth-service pytest
```

## Deployment

### Production Deployment

1. Update environment variables for production
2. Set `DEBUG=False`
3. Configure proper database (PostgreSQL)
4. Set up Redis for caching
5. Configure email backend
6. Use proper secret keys

### Docker Production

```bash
# Build production image
docker build -t auth-service:latest .

# Run with production settings
docker-compose --profile production up -d
```

## Monitoring

### Health Checks

The service provides health check endpoints:

- `/api/health/` - Overall service health
- Database connectivity check
- Cache connectivity check

### Logging

Logs are configured for different environments:

- Development: Console output
- Production: File and console output
- Structured logging with timestamps

## Security Features

- **Rate Limiting**: Prevents brute force attacks
- **JWT Blacklisting**: Invalidate tokens on logout
- **Password Validation**: Strong password requirements
- **CORS Configuration**: Controlled cross-origin access
- **Security Headers**: XSS, CSRF, and other protections
- **Input Validation**: Comprehensive request validation

## Microservice Integration

### Service-to-Service Authentication

Use the microservice key for internal communication:

```bash
curl -X GET http://auth-service:8000/api/users/ \
  -H "X-Microservice-Key: YOUR_MICROSERVICE_SECRET"
```

### User Verification

Other services can verify user tokens:

```bash
curl -X GET http://auth-service:8000/api/auth/me/ \
  -H "Authorization: Bearer USER_ACCESS_TOKEN"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run tests and ensure they pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
