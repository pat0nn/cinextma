# 🔗 Auth Service Integration Examples

## 📱 Frontend Integration

### React.js Integration

**1. Auth Context Provider**
```javascript
// contexts/AuthContext.js
import React, { createContext, useContext, useState, useEffect } from 'react';
import axios from 'axios';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tokens, setTokens] = useState({
    access: localStorage.getItem('access_token'),
    refresh: localStorage.getItem('refresh_token')
  });

  // Axios interceptor for automatic token attachment
  useEffect(() => {
    const requestInterceptor = axios.interceptors.request.use(
      (config) => {
        if (tokens.access) {
          config.headers.Authorization = `Bearer ${tokens.access}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    const responseInterceptor = axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401 && tokens.refresh) {
          try {
            const response = await axios.post('/api/auth/refresh/', {
              refresh_token: tokens.refresh
            });
            
            const newTokens = response.data.tokens;
            setTokens(newTokens);
            localStorage.setItem('access_token', newTokens.access_token);
            localStorage.setItem('refresh_token', newTokens.refresh_token);
            
            // Retry original request
            error.config.headers.Authorization = `Bearer ${newTokens.access_token}`;
            return axios.request(error.config);
          } catch (refreshError) {
            logout();
            return Promise.reject(refreshError);
          }
        }
        return Promise.reject(error);
      }
    );

    return () => {
      axios.interceptors.request.eject(requestInterceptor);
      axios.interceptors.response.eject(responseInterceptor);
    };
  }, [tokens]);

  const login = async (email, password) => {
    try {
      const response = await axios.post('/api/auth/login/', {
        email,
        password
      });
      
      const { tokens: newTokens, ...userData } = response.data;
      
      setTokens(newTokens);
      setUser(userData);
      
      localStorage.setItem('access_token', newTokens.access_token);
      localStorage.setItem('refresh_token', newTokens.refresh_token);
      
      return { success: true, user: userData };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || 'Login failed' 
      };
    }
  };

  const loginWithGoogle = async () => {
    try {
      // Get Google OAuth URL
      const urlResponse = await axios.post('/api/auth/google/url/', {
        state: Math.random().toString(36).substr(2, 9)
      });
      
      // Redirect to Google
      window.location.href = urlResponse.data.auth_url;
    } catch (error) {
      console.error('Google OAuth error:', error);
    }
  };

  const logout = async () => {
    try {
      if (tokens.access) {
        await axios.post('/api/auth/logout/');
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setUser(null);
      setTokens({ access: null, refresh: null });
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
    }
  };

  const getCurrentUser = async () => {
    try {
      if (!tokens.access) return null;
      
      const response = await axios.get('/api/auth/me/');
      setUser(response.data);
      return response.data;
    } catch (error) {
      if (error.response?.status === 401) {
        logout();
      }
      return null;
    }
  };

  useEffect(() => {
    getCurrentUser().finally(() => setLoading(false));
  }, []);

  const value = {
    user,
    loading,
    login,
    loginWithGoogle,
    logout,
    getCurrentUser,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
```

**2. Protected Route Component**
```javascript
// components/ProtectedRoute.js
import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const ProtectedRoute = ({ children, requireAuth = true }) => {
  const { user, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (requireAuth && !user) {
    return <Navigate to="/login" replace />;
  }

  if (!requireAuth && user) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
};

export default ProtectedRoute;
```

**3. Login Component**
```javascript
// components/Login.js
import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

const Login = () => {
  const [formData, setFormData] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login, loginWithGoogle } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    const result = await login(formData.email, formData.password);
    
    if (result.success) {
      navigate('/dashboard');
    } else {
      setError(result.error);
    }
    
    setLoading(false);
  };

  return (
    <div className="login-container">
      <form onSubmit={handleSubmit}>
        <h2>Login</h2>
        
        {error && <div className="error">{error}</div>}
        
        <input
          type="email"
          placeholder="Email"
          value={formData.email}
          onChange={(e) => setFormData({...formData, email: e.target.value})}
          required
        />
        
        <input
          type="password"
          placeholder="Password"
          value={formData.password}
          onChange={(e) => setFormData({...formData, password: e.target.value})}
          required
        />
        
        <button type="submit" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
        
        <button type="button" onClick={loginWithGoogle}>
          Login with Google
        </button>
      </form>
    </div>
  );
};

export default Login;
```

### Vue.js Integration

**1. Auth Store (Pinia)**
```javascript
// stores/auth.js
import { defineStore } from 'pinia';
import axios from 'axios';

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    tokens: {
      access: localStorage.getItem('access_token'),
      refresh: localStorage.getItem('refresh_token')
    },
    loading: false
  }),

  getters: {
    isAuthenticated: (state) => !!state.user,
    isLoading: (state) => state.loading
  },

  actions: {
    async login(email, password) {
      this.loading = true;
      try {
        const response = await axios.post('/api/auth/login/', {
          email,
          password
        });
        
        const { tokens, ...userData } = response.data;
        
        this.tokens = tokens;
        this.user = userData;
        
        localStorage.setItem('access_token', tokens.access_token);
        localStorage.setItem('refresh_token', tokens.refresh_token);
        
        return { success: true };
      } catch (error) {
        return { 
          success: false, 
          error: error.response?.data?.error || 'Login failed' 
        };
      } finally {
        this.loading = false;
      }
    },

    async logout() {
      try {
        if (this.tokens.access) {
          await axios.post('/api/auth/logout/', {}, {
            headers: { Authorization: `Bearer ${this.tokens.access}` }
          });
        }
      } catch (error) {
        console.error('Logout error:', error);
      } finally {
        this.user = null;
        this.tokens = { access: null, refresh: null };
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
      }
    },

    async getCurrentUser() {
      if (!this.tokens.access) return null;
      
      try {
        const response = await axios.get('/api/auth/me/', {
          headers: { Authorization: `Bearer ${this.tokens.access}` }
        });
        this.user = response.data;
        return response.data;
      } catch (error) {
        if (error.response?.status === 401) {
          this.logout();
        }
        return null;
      }
    }
  }
});
```

## 🖥️ Backend Service Integration

### Node.js/Express Integration

**1. Auth Middleware**
```javascript
// middleware/auth.js
const axios = require('axios');
const redis = require('redis');

const client = redis.createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});

const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    // Check cache first
    const cacheKey = `user:${token}`;
    const cachedUser = await client.get(cacheKey);
    
    if (cachedUser) {
      req.user = JSON.parse(cachedUser);
      return next();
    }

    // Validate with auth service
    const response = await axios.get(`${process.env.AUTH_SERVICE_URL}/api/auth/me/`, {
      headers: { Authorization: `Bearer ${token}` },
      timeout: 5000
    });
    
    req.user = response.data;
    
    // Cache for 5 minutes
    await client.setex(cacheKey, 300, JSON.stringify(response.data));
    
    next();
  } catch (error) {
    if (error.response?.status === 401) {
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    console.error('Auth service error:', error.message);
    return res.status(503).json({ error: 'Authentication service unavailable' });
  }
};

const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
};

module.exports = { authenticateUser, requireRole };
```

**2. User Service Routes**
```javascript
// routes/users.js
const express = require('express');
const { authenticateUser, requireRole } = require('../middleware/auth');

const router = express.Router();

// Get user profile
router.get('/profile', authenticateUser, async (req, res) => {
  try {
    // Get additional user data from local database
    const userProfile = await UserProfile.findOne({ userId: req.user.id });
    
    res.json({
      ...req.user,
      profile: userProfile
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to get user profile' });
  }
});

// Admin only route
router.get('/admin/users', authenticateUser, requireRole(['admin']), async (req, res) => {
  try {
    const users = await User.find({}).select('-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get users' });
  }
});

module.exports = router;
```

### Python/FastAPI Integration

**1. Auth Dependencies**
```python
# auth/dependencies.py
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer
import httpx
import redis
import json
from typing import Optional

security = HTTPBearer()
redis_client = redis.Redis.from_url("redis://localhost:6379")

async def get_current_user(token: str = Depends(security)) -> dict:
    """Validate user token with auth service"""
    
    # Check cache first
    cache_key = f"user:{token.credentials}"
    cached_user = redis_client.get(cache_key)
    
    if cached_user:
        return json.loads(cached_user)
    
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{settings.AUTH_SERVICE_URL}/api/auth/me/",
                headers={"Authorization": f"Bearer {token.credentials}"},
                timeout=5.0
            )
            
            if response.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token"
                )
            
            response.raise_for_status()
            user_data = response.json()
            
            # Cache for 5 minutes
            redis_client.setex(cache_key, 300, json.dumps(user_data))
            
            return user_data
            
        except httpx.RequestError:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Auth service unavailable"
            )

def require_role(allowed_roles: list):
    """Dependency to check user role"""
    def role_checker(current_user: dict = Depends(get_current_user)):
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker

# Specific role dependencies
get_admin_user = require_role(["admin"])
get_staff_user = require_role(["admin", "staff"])
```

**2. FastAPI Routes**
```python
# routes/orders.py
from fastapi import APIRouter, Depends
from auth.dependencies import get_current_user, get_admin_user

router = APIRouter(prefix="/api/orders", tags=["orders"])

@router.get("/")
async def get_user_orders(current_user: dict = Depends(get_current_user)):
    """Get orders for current user"""
    orders = await Order.filter(user_id=current_user["id"])
    return {"orders": orders, "user": current_user}

@router.get("/admin/all")
async def get_all_orders(admin_user: dict = Depends(get_admin_user)):
    """Get all orders (admin only)"""
    orders = await Order.all()
    return {"orders": orders, "admin": admin_user}

@router.post("/")
async def create_order(
    order_data: OrderCreate,
    current_user: dict = Depends(get_current_user)
):
    """Create new order"""
    order = await Order.create(
        **order_data.dict(),
        user_id=current_user["id"]
    )
    return {"order": order}
```

## 🐳 Docker Integration

**1. Multi-Service Docker Compose**
```yaml
# docker-compose.microservices.yml
version: '3.8'

services:
  # Auth Service
  auth-service:
    build: ./auth_service
    ports:
      - "8000:8000"
    environment:
      - DB_HOST=postgres
      - REDIS_URL=redis://redis:6379/1
      - MICROSERVICE_SECRET_KEY=shared-secret-key
    depends_on:
      - postgres
      - redis
    networks:
      - microservices

  # User Service (Node.js)
  user-service:
    build: ./user_service
    ports:
      - "3000:3000"
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8000
      - REDIS_URL=redis://redis:6379/2
    depends_on:
      - auth-service
      - redis
    networks:
      - microservices

  # Order Service (Python)
  order-service:
    build: ./order_service
    ports:
      - "8001:8000"
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8000
      - DATABASE_URL=postgresql://postgres:postgres@postgres:5432/orders
    depends_on:
      - auth-service
      - postgres
    networks:
      - microservices

  # API Gateway (Nginx)
  api-gateway:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - auth-service
      - user-service
      - order-service
    networks:
      - microservices

  # Shared Database
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: microservices
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - microservices

  # Shared Cache
  redis:
    image: redis:7-alpine
    networks:
      - microservices

networks:
  microservices:
    driver: bridge

volumes:
  postgres_data:
```

**2. API Gateway Configuration**
```nginx
# nginx/nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream auth_service {
        server auth-service:8000;
    }
    
    upstream user_service {
        server user-service:3000;
    }
    
    upstream order_service {
        server order-service:8000;
    }

    server {
        listen 80;
        
        # Auth service routes
        location /api/auth/ {
            proxy_pass http://auth_service;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        
        # User service routes
        location /api/users/ {
            proxy_pass http://user_service;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        
        # Order service routes
        location /api/orders/ {
            proxy_pass http://order_service;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
        
        # Health checks
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
}
```

## 📱 Mobile App Integration

**1. React Native Example**
```javascript
// services/AuthService.js
import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';

class AuthService {
  constructor() {
    this.baseURL = 'http://your-api-gateway.com/api';
    this.setupInterceptors();
  }

  setupInterceptors() {
    // Request interceptor
    axios.interceptors.request.use(async (config) => {
      const token = await AsyncStorage.getItem('access_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response interceptor for token refresh
    axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          const refreshToken = await AsyncStorage.getItem('refresh_token');
          if (refreshToken) {
            try {
              const response = await axios.post(`${this.baseURL}/auth/refresh/`, {
                refresh_token: refreshToken
              });
              
              const { tokens } = response.data;
              await this.storeTokens(tokens);
              
              // Retry original request
              error.config.headers.Authorization = `Bearer ${tokens.access_token}`;
              return axios.request(error.config);
            } catch (refreshError) {
              await this.logout();
              throw refreshError;
            }
          }
        }
        throw error;
      }
    );
  }

  async storeTokens(tokens) {
    await AsyncStorage.setItem('access_token', tokens.access_token);
    await AsyncStorage.setItem('refresh_token', tokens.refresh_token);
  }

  async login(email, password) {
    try {
      const response = await axios.post(`${this.baseURL}/auth/login/`, {
        email,
        password
      });
      
      const { tokens, ...userData } = response.data;
      await this.storeTokens(tokens);
      
      return { success: true, user: userData };
    } catch (error) {
      return { 
        success: false, 
        error: error.response?.data?.error || 'Login failed' 
      };
    }
  }

  async logout() {
    try {
      await axios.post(`${this.baseURL}/auth/logout/`);
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      await AsyncStorage.multiRemove(['access_token', 'refresh_token']);
    }
  }
}

export default new AuthService();
```

Các ví dụ này cho thấy cách tích hợp auth-service với nhiều loại ứng dụng và framework khác nhau, đảm bảo tính nhất quán và bảo mật trong toàn bộ hệ thống microservice! 🚀
