#!/usr/bin/env python3
"""
Script to test Google OAuth flow manually.
"""
import requests
import json
import sys
from urllib.parse import urlparse, parse_qs

def test_google_oauth():
    base_url = "http://localhost:8000/api"
    
    print("🔐 Testing Google OAuth Flow")
    print("=" * 40)
    
    # Step 1: Get Google OAuth URL
    print("\n1. Getting Google OAuth URL...")
    try:
        response = requests.post(f"{base_url}/auth/google/url/", 
                               json={"state": "test_script"})
        response.raise_for_status()
        
        oauth_data = response.json()
        auth_url = oauth_data['auth_url']
        
        print(f"✅ OAuth URL generated successfully")
        print(f"🔗 URL: {auth_url}")
        
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to get OAuth URL: {e}")
        return False
    
    # Step 2: Manual intervention needed
    print(f"\n2. Manual step required:")
    print(f"   - Open the URL above in your browser")
    print(f"   - Login with your Google account")
    print(f"   - Copy the 'code' parameter from the callback URL")
    print(f"   - The callback URL will look like:")
    print(f"     http://localhost:8000/api/auth/google/callback/?code=XXXXX&state=test_script")
    
    # Get code from user
    print(f"\n3. Enter the authorization code:")
    code = input("Code: ").strip()
    
    if not code:
        print("❌ No code provided")
        return False
    
    # Step 3: Test OAuth callback
    print(f"\n4. Testing OAuth callback...")
    try:
        response = requests.post(f"{base_url}/auth/google/callback/", 
                               json={
                                   "code": code,
                                   "state": "test_script"
                               })
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Google OAuth login successful!")
            print(f"📧 Email: {result.get('email')}")
            print(f"🆔 User ID: {result.get('user_id')}")
            print(f"🆕 New user: {result.get('is_new_user')}")
            print(f"🔑 Access token: {result.get('tokens', {}).get('access_token', '')[:50]}...")
            print(f"🔄 Refresh token: {result.get('tokens', {}).get('refresh_token', '')[:50]}...")
            
            # Test the access token
            access_token = result.get('tokens', {}).get('access_token')
            if access_token:
                print(f"\n5. Testing access token...")
                me_response = requests.get(f"{base_url}/auth/me/", 
                                         headers={"Authorization": f"Bearer {access_token}"})
                
                if me_response.status_code == 200:
                    user_data = me_response.json()
                    print(f"✅ Access token works!")
                    print(f"👤 User data: {json.dumps(user_data, indent=2)}")
                else:
                    print(f"❌ Access token test failed: {me_response.status_code}")
                    print(f"Response: {me_response.text}")
            
            return True
            
        else:
            print(f"❌ OAuth callback failed: {response.status_code}")
            print(f"Response: {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to test OAuth callback: {e}")
        return False

def test_health_check():
    """Test if the auth service is running."""
    try:
        response = requests.get("http://localhost:8000/api/health/", timeout=5)
        if response.status_code == 200:
            print("✅ Auth service is running")
            return True
        else:
            print(f"❌ Auth service health check failed: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Cannot connect to auth service: {e}")
        print("Make sure the server is running: python manage.py runserver")
        return False

if __name__ == "__main__":
    print("🚀 Auth Service Google OAuth Test Script")
    print("=" * 50)
    
    # Check if service is running
    if not test_health_check():
        sys.exit(1)
    
    # Run OAuth test
    success = test_google_oauth()
    
    if success:
        print(f"\n🎉 Google OAuth test completed successfully!")
    else:
        print(f"\n💥 Google OAuth test failed!")
        sys.exit(1)
