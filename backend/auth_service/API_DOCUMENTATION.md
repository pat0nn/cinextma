# Auth Service API Documentation

## Base URL
```
http://localhost:8000/api
```

## Authentication

All authenticated endpoints require a Bearer token in the Authorization header:
```
Authorization: Bearer <access_token>
```

## Response Format

All API responses follow this format:

### Success Response
```json
{
  "data": {...},
  "message": "Success message (optional)"
}
```

### Error Response
```json
{
  "error": "Error message",
  "details": {...} // Optional additional error details
}
```

## Endpoints

### Authentication Endpoints

#### Register User
```http
POST /auth/register/
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "password_confirm": "securepassword123",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response (201):**
```json
{
  "user_id": "uuid",
  "email": "user@example.com",
  "message": "User registered successfully. Please check your email for verification."
}
```

#### Login User
```http
POST /auth/login/
```

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securepassword123",
  "device_id": "optional_device_id",
  "device_name": "optional_device_name"
}
```

**Response (200):**
```json
{
  "user_id": "uuid",
  "email": "user@example.com",
  "tokens": {
    "access_token": "jwt_access_token",
    "refresh_token": "jwt_refresh_token",
    "access_token_expires_at": "2024-01-01T12:00:00Z",
    "refresh_token_expires_at": "2024-01-08T12:00:00Z"
  }
}
```

#### Logout User
```http
POST /auth/logout/
```
*Requires authentication*

**Response (200):**
```json
{
  "message": "Logged out successfully"
}
```

#### Refresh Token
```http
POST /auth/refresh/
```

**Request Body:**
```json
{
  "refresh_token": "jwt_refresh_token"
}
```

**Response (200):**
```json
{
  "user_id": "uuid",
  "tokens": {
    "access_token": "new_jwt_access_token",
    "refresh_token": "new_jwt_refresh_token",
    "access_token_expires_at": "2024-01-01T12:00:00Z",
    "refresh_token_expires_at": "2024-01-08T12:00:00Z"
  }
}
```

#### Get Current User
```http
GET /auth/me/
```
*Requires authentication*

**Response (200):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "full_name": "John Doe",
  "is_active": true,
  "is_staff": false,
  "is_superuser": false,
  "is_verified": true,
  "role": "user",
  "avatar": "https://example.com/avatar.jpg",
  "last_login_at": "2024-01-01T12:00:00Z",
  "created_at": "2024-01-01T10:00:00Z"
}
```

#### Update Current User
```http
PUT /auth/me/
```
*Requires authentication*

**Request Body:**
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+1234567890",
  "avatar": "https://example.com/new-avatar.jpg"
}
```

### Password Management

#### Request Password Reset
```http
POST /auth/password/reset/request/
```

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "If the email exists, a password reset link has been sent"
}
```

#### Reset Password
```http
POST /auth/password/reset/
```

**Request Body:**
```json
{
  "token": "reset_token_from_email",
  "new_password": "newsecurepassword123",
  "new_password_confirm": "newsecurepassword123"
}
```

**Response (200):**
```json
{
  "user_id": "uuid",
  "message": "Password reset successfully"
}
```

#### Change Password
```http
POST /auth/password/change/
```
*Requires authentication*

**Request Body:**
```json
{
  "old_password": "oldsecurepassword123",
  "new_password": "newsecurepassword123",
  "new_password_confirm": "newsecurepassword123"
}
```

**Response (200):**
```json
{
  "message": "Password changed successfully"
}
```

### Email Verification

#### Verify Email
```http
POST /auth/email/verify/
```

**Request Body:**
```json
{
  "token": "verification_token_from_email"
}
```

**Response (200):**
```json
{
  "user_id": "uuid",
  "message": "Email verified successfully"
}
```

#### Resend Verification Email
```http
POST /auth/email/resend/
```
*Requires authentication*

**Response (200):**
```json
{
  "message": "Verification email sent successfully"
}
```

### Google OAuth

#### Get Google OAuth URL
```http
POST /auth/google/url/
```

**Request Body:**
```json
{
  "state": "optional_state_parameter"
}
```

**Response (200):**
```json
{
  "auth_url": "https://accounts.google.com/o/oauth2/auth?..."
}
```

#### Google OAuth Callback
```http
POST /auth/google/callback/
```

**Request Body:**
```json
{
  "code": "authorization_code_from_google",
  "state": "optional_state_parameter"
}
```

**Response (200):**
```json
{
  "user_id": "uuid",
  "email": "user@gmail.com",
  "tokens": {
    "access_token": "jwt_access_token",
    "refresh_token": "jwt_refresh_token",
    "access_token_expires_at": "2024-01-01T12:00:00Z",
    "refresh_token_expires_at": "2024-01-08T12:00:00Z"
  },
  "is_new_user": false
}
```

### User Management

#### List Users
```http
GET /users/
```
*Requires admin authentication*

**Query Parameters:**
- `page`: Page number (default: 1)
- `is_active`: Filter by active status (true/false)
- `is_verified`: Filter by verification status (true/false)
- `role`: Filter by role (user/admin)
- `search`: Search in email, first_name, last_name

**Response (200):**
```json
{
  "results": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "full_name": "John Doe",
      "is_active": true,
      "is_verified": true,
      "role": "user",
      "created_at": "2024-01-01T10:00:00Z"
    }
  ],
  "count": 1,
  "page": 1,
  "page_size": 20
}
```

#### Get User Details
```http
GET /users/{user_id}/
```
*Requires authentication (own profile) or admin*

**Response (200):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "full_name": "John Doe",
  "phone_number": "+1234567890",
  "is_active": true,
  "is_verified": true,
  "role": "user",
  "avatar": "https://example.com/avatar.jpg",
  "created_at": "2024-01-01T10:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

#### Update User
```http
PUT /users/{user_id}/
```
*Requires authentication (own profile) or admin*

**Request Body:**
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "phone_number": "+1234567890",
  "avatar": "https://example.com/new-avatar.jpg"
}
```

#### Get User Profile
```http
GET /users/{user_id}/profile/
```
*Requires authentication (own profile) or admin*

**Response (200):**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "full_name": "John Doe",
  "phone_number": "+1234567890",
  "avatar": "https://example.com/avatar.jpg",
  "is_verified": true,
  "role": "user",
  "profile": {
    "bio": "Software developer",
    "location": "New York",
    "website": "https://johndoe.com",
    "twitter_url": "https://twitter.com/johndoe",
    "linkedin_url": "https://linkedin.com/in/johndoe",
    "github_url": "https://github.com/johndoe",
    "timezone": "UTC",
    "language": "en",
    "email_notifications": true,
    "push_notifications": true
  },
  "created_at": "2024-01-01T10:00:00Z",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

#### Update User Profile
```http
PUT /users/{user_id}/profile/
```
*Requires authentication (own profile) or admin*

**Request Body:**
```json
{
  "bio": "Updated bio",
  "location": "San Francisco",
  "website": "https://newwebsite.com",
  "timezone": "America/Los_Angeles",
  "email_notifications": false
}
```

### Health Check

#### Service Health
```http
GET /health/
```

**Response (200):**
```json
{
  "service": "auth-service",
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-01T12:00:00Z",
  "database": "connected",
  "cache": "connected"
}
```

## Error Codes

| Status Code | Description |
|-------------|-------------|
| 400 | Bad Request - Invalid input data |
| 401 | Unauthorized - Authentication required |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server error |

## Rate Limits

- Login attempts: 5 per 5 minutes per IP
- Registration: 3 per hour per IP
- Password reset: 3 per hour per IP
- General API: 100 per hour per IP

## Microservice Integration

For service-to-service communication, use the microservice key:

```http
X-Microservice-Key: your_microservice_secret_key
```

This bypasses normal authentication for internal service communication.
