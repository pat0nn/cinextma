# 🧪 Hướng dẫn Test Auth Service với Insomnia

## 📥 Import Collection

1. **Mở Insomnia**
2. **Import Collection**: 
   - Click `Create` → `Import From` → `File`
   - Chọn file `insomnia_test_collection.json`
3. **Chọn Workspace**: `Auth Service API`

## 🔧 Cấu hình Environment

Trong Insomnia, chọn environment `Base Environment` và cập nhật các biến:

```json
{
  "base_url": "http://localhost:8000",
  "test_email": "test@example.com", 
  "test_password": "testpassword123",
  "new_password": "newpassword123",
  "access_token": "",
  "refresh_token": "",
  "google_auth_code": ""
}
```

## 🚀 Kịch bản Test Hoàn chỉnh

### 📋 Scenario 1: Basic Authentication Flow

**Bước 1: Health Check**
```
GET /api/health/
```
- ✅ Kiểm tra service hoạt động
- Expected: Status 200, response có `status: "healthy"`

**Bước 2: Register User**
```
POST /api/auth/register/
{
  "email": "test@example.com",
  "password": "testpassword123", 
  "password_confirm": "testpassword123",
  "first_name": "Test",
  "last_name": "User"
}
```
- ✅ Tạo user mới
- Expected: Status 201, response có `user_id` và `email`

**Bước 3: Login User**
```
POST /api/auth/login/
{
  "email": "test@example.com",
  "password": "testpassword123",
  "device_id": "insomnia_test",
  "device_name": "Insomnia Test Client"
}
```
- ✅ Đăng nhập và lấy tokens
- Expected: Status 200, response có `tokens` object
- **📝 Action**: Copy `access_token` và `refresh_token` vào environment

**Bước 4: Get Current User**
```
GET /api/auth/me/
Authorization: Bearer {access_token}
```
- ✅ Lấy thông tin user hiện tại
- Expected: Status 200, response có thông tin user

**Bước 5: Update Current User**
```
PUT /api/auth/me/
Authorization: Bearer {access_token}
{
  "first_name": "Updated",
  "last_name": "Name",
  "phone_number": "+84123456789"
}
```
- ✅ Cập nhật thông tin user
- Expected: Status 200, response có thông tin đã cập nhật

**Bước 6: Refresh Token**
```
POST /api/auth/refresh/
{
  "refresh_token": "{refresh_token}"
}
```
- ✅ Làm mới access token
- Expected: Status 200, response có tokens mới
- **📝 Action**: Cập nhật tokens mới vào environment

**Bước 7: Logout**
```
POST /api/auth/logout/
Authorization: Bearer {access_token}
```
- ✅ Đăng xuất và blacklist tokens
- Expected: Status 200, message thành công

### 📋 Scenario 2: Google OAuth Flow

**Bước 1: Get Google OAuth URL**
```
POST /api/auth/google/url/
{
  "state": "insomnia_test_123456"
}
```
- ✅ Lấy URL để redirect đến Google
- Expected: Status 200, response có `auth_url`
- **📝 Action**: Copy `auth_url` và mở trong browser

**Bước 2: Manual Google Login**
- Mở `auth_url` trong browser
- Đăng nhập với Google account
- Copy `code` parameter từ callback URL

**Bước 3: Google OAuth Callback**
```
POST /api/auth/google/callback/
{
  "code": "{google_auth_code}",
  "state": "insomnia_test_123456"
}
```
- ✅ Xử lý callback và lấy tokens
- Expected: Status 200, response có `tokens` và `user_id`
- **📝 Action**: Cập nhật tokens vào environment

### 📋 Scenario 3: Password Management

**Bước 1: Request Password Reset**
```
POST /api/auth/password/reset/request/
{
  "email": "test@example.com"
}
```
- ✅ Yêu cầu reset password
- Expected: Status 200, message thành công

**Bước 2: Change Password (cần đăng nhập)**
```
POST /api/auth/password/change/
Authorization: Bearer {access_token}
{
  "old_password": "testpassword123",
  "new_password": "newpassword123",
  "new_password_confirm": "newpassword123"
}
```
- ✅ Đổi password
- Expected: Status 200, message thành công

## 🔍 Test Cases Chi tiết

### ✅ Positive Test Cases

1. **Health Check**: Service hoạt động bình thường
2. **User Registration**: Tạo user mới thành công
3. **User Login**: Đăng nhập thành công với credentials đúng
4. **Token Refresh**: Làm mới token thành công
5. **User Profile**: Lấy và cập nhật thông tin user
6. **Google OAuth**: Flow OAuth hoàn chỉnh
7. **Password Management**: Đổi password thành công
8. **Logout**: Đăng xuất và blacklist tokens

### ❌ Negative Test Cases

**Test với Invalid Data:**

1. **Register với email trùng**:
   ```json
   {
     "email": "test@example.com", // Email đã tồn tại
     "password": "testpassword123",
     "password_confirm": "testpassword123"
   }
   ```
   Expected: Status 400, error message

2. **Login với password sai**:
   ```json
   {
     "email": "test@example.com",
     "password": "wrongpassword"
   }
   ```
   Expected: Status 400, error message

3. **Access protected endpoint không có token**:
   ```
   GET /api/auth/me/
   // Không có Authorization header
   ```
   Expected: Status 401, unauthorized

4. **Refresh với invalid token**:
   ```json
   {
     "refresh_token": "invalid_token"
   }
   ```
   Expected: Status 400, error message

## 📊 Expected Response Formats

### Success Login Response:
```json
{
  "user_id": "uuid",
  "email": "test@example.com",
  "tokens": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "access_token_expires_at": "2024-01-01T12:15:00Z",
    "refresh_token_expires_at": "2024-01-08T12:00:00Z"
  }
}
```

### Error Response:
```json
{
  "error": "Error message description"
}
```

## 🎯 Tips cho Testing

1. **Environment Variables**: Luôn cập nhật tokens vào environment sau mỗi login
2. **Token Expiry**: Access token hết hạn sau 15 phút, test refresh flow
3. **State Parameter**: Sử dụng unique state cho mỗi OAuth request
4. **Error Handling**: Test cả success và error cases
5. **Sequential Testing**: Chạy theo thứ tự để đảm bảo dependencies

## 🔧 Troubleshooting

**Lỗi 500 Internal Server Error:**
- Kiểm tra server có chạy không: `http://localhost:8000/api/health/`
- Kiểm tra database connection
- Xem logs trong terminal

**Lỗi 401 Unauthorized:**
- Kiểm tra access token có đúng không
- Token có hết hạn không
- Header Authorization có đúng format: `Bearer {token}`

**Google OAuth lỗi:**
- Kiểm tra Google OAuth credentials trong .env
- Redirect URI có đúng không
- State parameter có match không
