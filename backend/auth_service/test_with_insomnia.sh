#!/bin/bash

# Script để setup và test Auth Service với Insomnia

set -e

echo "🚀 Auth Service - Insomnia Test Setup"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    print_status "Tạo virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
print_status "Kích hoạt virtual environment..."
source venv/bin/activate

# Install dependencies
print_status "Cài đặt dependencies..."
pip install -r requirements/local.txt

# Check if .env exists
if [ ! -f ".env" ]; then
    print_warning ".env file không tồn tại, tạo từ .env.example..."
    cp .env.example .env
    print_warning "Vui lòng cập nhật .env với thông tin thực tế!"
fi

# Run migrations
print_status "Chạy database migrations..."
python manage.py makemigrations
python manage.py migrate

# Create superuser if not exists
print_status "Tạo superuser (nếu chưa có)..."
python manage.py shell << EOF
from django.contrib.auth import get_user_model
import os

User = get_user_model()

if not User.objects.filter(is_superuser=True).exists():
    User.objects.create_superuser(
        email='admin@example.com',
        password='admin123'
    )
    print("✅ Superuser created: admin@example.com / admin123")
else:
    print("ℹ️ Superuser already exists")
EOF

# Check server health
print_status "Kiểm tra server health..."
python manage.py check

print_success "Setup hoàn tất!"
echo ""
echo "📋 Hướng dẫn sử dụng:"
echo "===================="
echo ""
echo "1. 🚀 Chạy server:"
echo "   python manage.py runserver 0.0.0.0:8000"
echo ""
echo "2. 📥 Import Insomnia Collection:"
echo "   - Mở Insomnia"
echo "   - Import file: insomnia_test_collection.json"
echo "   - Chọn workspace: 'Auth Service API'"
echo ""
echo "3. 🔧 Cấu hình Environment trong Insomnia:"
echo "   - base_url: http://localhost:8000"
echo "   - test_email: test@example.com"
echo "   - test_password: testpassword123"
echo ""
echo "4. 🧪 Chạy test theo thứ tự:"
echo "   - Health Check"
echo "   - Register User"
echo "   - Login User (copy tokens vào environment)"
echo "   - Get Current User"
echo "   - Update Current User"
echo "   - Refresh Token"
echo "   - Logout"
echo ""
echo "5. 🌐 Test Google OAuth:"
echo "   - Get Google OAuth URL"
echo "   - Mở URL trong browser và đăng nhập"
echo "   - Copy code từ callback URL"
echo "   - Chạy Google OAuth Callback"
echo ""
echo "6. ❌ Test Negative Cases:"
echo "   - Register Duplicate Email"
echo "   - Login Wrong Password"
echo "   - Access /me Without Token"
echo "   - Refresh Invalid Token"
echo ""
echo "📚 Tài liệu chi tiết: INSOMNIA_TEST_GUIDE.md"
echo ""
echo "🔗 Useful URLs:"
echo "   - Health Check: http://localhost:8000/api/health/"
echo "   - Admin Panel: http://localhost:8000/admin/"
echo "   - API Docs: Xem INSOMNIA_TEST_GUIDE.md"
echo ""
echo "🎯 Ready to test! Chạy server và bắt đầu test với Insomnia."
