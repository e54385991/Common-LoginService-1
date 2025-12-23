# Common Login Service

A unified authentication service built with Go Gin framework, featuring Google OAuth login and Gmail API password recovery.

统一登录/注册服务系统，基于 Go Gin 框架开发，支持 Google OAuth 登录和 Gmail API 邮件找回功能。

## Features / 功能特性

- ✅ User Registration and Login / 用户注册和登录
- ✅ Google OAuth One-Click Login / Google OAuth 一键登录
- ✅ Gmail API Password Reset / Gmail API 密码重置邮件
- ✅ JWT Token Authentication / JWT Token 身份验证
- ✅ Configurable Session Storage (MySQL/Redis) / 可配置会话存储（MySQL/Redis）
- ✅ Admin Backend Configuration / 管理后台配置
- ✅ User Balance Management / 用户余额管理
- ✅ User VIP Level System / 用户 VIP 等级系统
- ✅ RESTful API / RESTful API 接口
- ✅ i18n Support (English/Chinese) / 国际化支持（英语/中文）
- ✅ Beautiful Responsive UI / 美观的响应式界面

## Quick Start / 快速开始

### Requirements / 环境要求

- Go 1.25+
- MySQL 8.4+
- Redis 6.0+ (optional, for Redis session storage) / Redis 6.0+（可选，用于 Redis 会话存储）

### Installation / 安装运行

```bash
# Clone the project / 克隆项目
git clone https://github.com/e54385991/Common-LoginService.git
cd Common-LoginService

# Install dependencies / 安装依赖
go mod tidy

# Run the service / 运行服务
go run cmd/main.go
```

The service will start at `http://localhost:8080`.

服务将在 `http://localhost:8080` 启动。

### Default Admin Account / 默认管理员账户

- Username / 用户名: `admin`
- Password / 密码: `admin123`
- Admin Panel / 管理后台: `http://localhost:8080/admin/login`

## Configuration / 配置说明

Create a `config.json` file:

创建 `config.json` 文件进行配置：

```json
{
  "server": {
    "port": "8080",
    "host": "0.0.0.0"
  },
  "database": {
    "host": "127.0.0.1",
    "port": "3306",
    "user": "root",
    "password": "your-password",
    "dbname": "login_service",
    "charset": "utf8mb4"
  },
  "jwt": {
    "secret": "your-secret-key-change-in-production",
    "expire_hour": 24
  },
  "session": {
    "storage_type": "mysql",
    "redis": {
      "host": "127.0.0.1",
      "port": "6379",
      "password": "",
      "db": 0,
      "key_prefix": "session:"
    }
  },
  "google_oauth": {
    "enabled": true,
    "client_id": "your-google-client-id",
    "client_secret": "your-google-client-secret",
    "redirect_url": "http://localhost:8080/api/auth/google/callback"
  },
  "gmail_api": {
    "enabled": true,
    "credentials_file": "credentials.json",
    "token_file": "token.json",
    "sender_email": "your-email@gmail.com"
  },
  "admin": {
    "username": "admin",
    "password": "admin123"
  },
  "signed_url": {
    "enabled": true,
    "secret": "your-hmac-secret-key-at-least-32-chars",
    "expire_seconds": 300
  }
}
```

### Session Storage / 会话存储

User login sessions are stored server-side and can be configured to use either MySQL or Redis.

用户登录会话存储在服务器端，可以配置使用 MySQL 或 Redis。

**How Sessions Work / 会话工作原理：**
- When a user logs in, a JWT token is generated and returned to the client
- 用户登录时，会生成 JWT 令牌并返回给客户端
- A SHA256 hash of the token is stored server-side (MySQL or Redis) for session tracking
- 令牌的 SHA256 哈希值存储在服务器端（MySQL 或 Redis）用于会话跟踪
- On each request, the token is validated and checked against the stored session
- 每次请求时，令牌会被验证并与存储的会话进行核对
- Sessions can be invalidated by deleting them from storage (e.g., on logout)
- 会话可以通过从存储中删除来失效（例如，在退出登录时）

**Storage Types / 存储类型：**
- `mysql` (default): Sessions are stored in the MySQL database / 会话存储在 MySQL 数据库中
- `redis`: Sessions are stored in Redis with automatic TTL expiration / 会话存储在 Redis 中，支持自动 TTL 过期

**Encryption / 加密说明：**
- JWT tokens are signed using HMAC-SHA256 algorithm / JWT 令牌使用 HMAC-SHA256 算法签名
- The JWT secret key is configurable via `jwt.secret` in config or `JWT_SECRET` environment variable
- JWT 密钥可通过配置文件中的 `jwt.secret` 或环境变量 `JWT_SECRET` 进行配置
- User passwords are hashed using bcrypt / 用户密码使用 bcrypt 进行哈希处理
- Session tokens are stored as SHA256 hashes (not plain text) / 会话令牌以 SHA256 哈希值存储（非明文）

### Environment Variables / 环境变量

Configuration can also be done via environment variables:

也可以通过环境变量进行配置：

- `SERVER_PORT` - Server port / 服务端口
- `JWT_SECRET` - JWT secret key / JWT 密钥
- `GOOGLE_CLIENT_ID` - Google OAuth Client ID
- `GOOGLE_CLIENT_SECRET` - Google OAuth Client Secret
- `DB_HOST` - Database host / 数据库主机
- `DB_PORT` - Database port / 数据库端口
- `DB_USER` - Database user / 数据库用户
- `DB_PASSWORD` - Database password / 数据库密码
- `DB_NAME` - Database name / 数据库名称
- `SESSION_STORAGE_TYPE` - Session storage type (`mysql` or `redis`) / 会话存储类型
- `REDIS_HOST` - Redis host / Redis 主机
- `REDIS_PORT` - Redis port / Redis 端口
- `REDIS_PASSWORD` - Redis password / Redis 密码
- `REDIS_KEY_PREFIX` - Redis key prefix for sessions / Redis 会话键前缀
- `SIGNED_URL_SECRET` - HMAC secret for signed URL callbacks / 签名URL回调的HMAC密钥

## API Documentation / API 接口文档

### Swagger UI / 交互式 API 文档

This project includes Swagger/OpenAPI documentation for interactive API exploration.

本项目集成了 Swagger/OpenAPI 文档，支持交互式 API 浏览。

- **Swagger UI**: `http://localhost:8080/swagger/index.html`
- **OpenAPI Spec (JSON)**: `http://localhost:8080/swagger/doc.json`
- **OpenAPI Spec (YAML)**: Available in `docs/swagger.yaml`

#### Regenerate API Documentation / 重新生成 API 文档

If you modify API endpoints, regenerate the documentation:

如果修改了 API 端点，请重新生成文档：

```bash
# Install swag CLI / 安装 swag CLI
go install github.com/swaggo/swag/cmd/swag@latest

# Generate documentation / 生成文档
swag init -g cmd/main.go -o docs --parseDependency --parseInternal
```

### User Authentication / 用户认证

#### Register / 注册

```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "password123",
  "display_name": "Display Name"
}
```

#### Login / 登录

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

#### Logout / 登出

```http
POST /api/auth/logout
```

#### Get Profile / 获取用户信息

```http
GET /api/auth/profile
Authorization: Bearer <token>
```

#### Validate Token / 验证 Token

```http
POST /api/auth/validate
Content-Type: application/json

{
  "token": "jwt-token"
}
```

#### Forgot Password / 忘记密码

```http
POST /api/auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### Reset Password / 重置密码

```http
POST /api/auth/reset-password
Content-Type: application/json

{
  "token": "reset-token",
  "new_password": "new-password123"
}
```

### Google OAuth

#### Get Google OAuth Status / 获取 Google OAuth 状态

```http
GET /api/auth/google/status
```

#### Google Login (Redirect) / Google 登录（重定向方式）

```http
GET /api/auth/google/login
```

#### Google Login (API) / Google 登录（API 方式）

```http
POST /api/auth/google/login
Content-Type: application/json

{
  "id_token": "google-id-token"
}
```

### Admin User Management API / 管理员用户管理 API

These endpoints require admin authentication (admin session cookie).

这些接口需要管理员身份验证（管理员会话 Cookie）。

#### Get User by ID / 获取用户信息

```http
GET /api/admin/users/{id}
```

Response / 响应:
```json
{
  "success": true,
  "data": {
    "id": 1,
    "email": "user@example.com",
    "username": "johndoe",
    "display_name": "John Doe",
    "balance": 100.50,
    "vip_level": 2,
    "is_active": true,
    "is_admin": false
  }
}
```

#### Update User Balance / 更新用户余额（增减）

```http
POST /api/admin/users/{id}/balance
Content-Type: application/json

{
  "amount": 50.00
}
```

Use positive values to add balance, negative values to subtract.

正数表示增加余额，负数表示减少余额。

#### Set User Balance / 设置用户余额（直接设置）

```http
PUT /api/admin/users/{id}/balance
Content-Type: application/json

{
  "balance": 200.00
}
```

#### Set User VIP Level / 设置用户 VIP 等级

```http
PUT /api/admin/users/{id}/vip-level
Content-Type: application/json

{
  "vip_level": 3
}
```

VIP level 0 represents a normal user.

VIP 等级 0 表示普通用户。

#### Set User Status / 设置用户状态

```http
PUT /api/admin/users/{id}/status
Content-Type: application/json

{
  "is_active": true
}
```

### External API (Token Authentication) / 外部API（令牌认证）

These endpoints require API token authentication via `X-API-Key` header or `Authorization: Bearer <token>`.

这些接口需要通过 `X-API-Key` 头或 `Authorization: Bearer <token>` 进行 API 令牌认证。

#### Create API Token / 创建 API 令牌

API tokens can be created in the admin panel at `/admin/api-tokens`. Available permissions:
- `balance` - Update user balance / 更新用户余额
- `vip` - Set VIP level and expiration / 设置 VIP 等级和到期时间
- `password` - Set user password / 设置用户密码
- `user` - Create new users / 创建新用户
- `all` - All permissions / 所有权限

#### Get User Info / 获取用户信息

```http
GET /api/external/user?user_id=123
X-API-Key: your-api-token
```

Response / 响应:
```json
{
  "success": true,
  "data": {
    "id": 123,
    "username": "johndoe",
    "email": "user@example.com",
    "balance": 100.50,
    "vip_level": 2,
    "vip_expire_at": "2025-12-31T23:59:59Z",
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

#### Update User Balance / 更新用户余额

Requires `balance` or `all` permission.

需要 `balance` 或 `all` 权限。

```http
POST /api/external/balance
X-API-Key: your-api-token
Content-Type: application/json

{
  "user_id": 123,
  "amount": 50.00,
  "reason": "API recharge"
}
```

Use positive values to add balance, negative values to subtract.

正数表示增加余额，负数表示减少余额。

#### Set User VIP Level / 设置用户 VIP 等级

Requires `vip` or `all` permission.

需要 `vip` 或 `all` 权限。

```http
POST /api/external/vip-level
X-API-Key: your-api-token
Content-Type: application/json

{
  "user_id": 123,
  "vip_level": 3
}
```

#### Set User VIP Expiration / 设置用户 VIP 到期时间

Requires `vip` or `all` permission.

需要 `vip` 或 `all` 权限。

```http
POST /api/external/vip-expire
X-API-Key: your-api-token
Content-Type: application/json

{
  "user_id": 123,
  "vip_expire_at": "2025-12-31T23:59:59Z"
}
```

Set `vip_expire_at` to empty string to clear expiration (permanent VIP).

将 `vip_expire_at` 设为空字符串可清除到期时间（永久 VIP）。

#### Set User Password / 设置用户密码

Requires `password` or `all` permission.

需要 `password` 或 `all` 权限。

```http
POST /api/external/password
X-API-Key: your-api-token
Content-Type: application/json

{
  "user_id": 123,
  "password": "newpassword123"
}
```

#### Create User / 创建用户

Requires `user` or `all` permission. Supports setting specific ID, initial balance, VIP level, and VIP expiration.

需要 `user` 或 `all` 权限。支持设置指定 ID、初始余额、VIP 等级和 VIP 到期时间。

```http
POST /api/external/user
X-API-Key: your-api-token
Content-Type: application/json

{
  "id": 100,
  "email": "newuser@example.com",
  "username": "newuser",
  "password": "password123",
  "display_name": "New User",
  "balance": 100.00,
  "vip_level": 1,
  "vip_expire_at": "2025-12-31T23:59:59Z",
  "is_active": true
}
```

| Parameter | Required | Description | 说明 |
|-----------|----------|-------------|------|
| `id` | No | Force specific user ID | 强制指定用户 ID |
| `email` | Yes | User email address | 用户邮箱地址 |
| `username` | Yes | Unique username (3-30 chars, alphanumeric and underscore) | 唯一用户名（3-30字符，字母数字下划线） |
| `password` | Yes | Password (min 6 chars) | 密码（至少6个字符） |
| `display_name` | No | Display name (defaults to username) | 显示名称（默认为用户名） |
| `balance` | No | Initial balance (default 0) | 初始余额（默认0） |
| `vip_level` | No | VIP level (default 0) | VIP 等级（默认0） |
| `vip_expire_at` | No | VIP expiration time (ISO 8601 format) | VIP 到期时间（ISO 8601 格式） |
| `is_active` | No | Account active status (default true) | 账户激活状态（默认 true） |

Response / 响应:
```json
{
  "success": true,
  "message": "用户创建成功",
  "data": {
    "id": 100,
    "username": "newuser",
    "email": "newuser@example.com",
    "display_name": "New User",
    "balance": 100.00,
    "vip_level": 1,
    "vip_expire_at": "2025-12-31T23:59:59Z",
    "is_active": true,
    "created_at": "2024-01-15T10:30:00Z"
  }
}
```

## Third-Party Integration / 第三方系统集成

### Integration Overview / 集成概述

Common Login Service provides a simple way for your applications to authenticate users and get their unique ID.

Common Login Service 提供了一种简单的方式让您的应用程序验证用户身份并获取用户唯一 ID。

### Complete Integration Example / 完整集成示例

#### Step 1: User Login Flow / 步骤1：用户登录流程

```javascript
// In your application frontend / 在您的应用前端
// Redirect user to login page / 将用户重定向到登录页面
window.location.href = 'https://your-login-service.com/auth/login?redirect=https://your-app.com/callback';

// Or call login API directly / 或直接调用登录 API
async function login(email, password) {
  const response = await fetch('https://your-login-service.com/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await response.json();
  if (data.success) {
    // Save token for later use / 保存 token 以便后续使用
    localStorage.setItem('auth_token', data.data.token);
    return data.data;
  }
  throw new Error(data.message);
}
```

#### Step 2: Validate Token and Get User ID / 步骤2：验证 Token 并获取用户 ID

```javascript
// Validate token and get user unique ID / 验证 token 并获取用户唯一 ID
async function validateAndGetUserId(token) {
  const response = await fetch('https://your-login-service.com/api/auth/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  });
  const data = await response.json();
  
  if (data.success && data.data.valid) {
    // User unique ID is in data.data.user.id
    // 用户唯一 ID 在 data.data.user.id 中
    const userId = data.data.user.id;
    const email = data.data.user.email;
    const username = data.data.user.username;
    const displayName = data.data.user.display_name;
    
    return {
      userId,      // Unique user ID / 用户唯一 ID
      email,       // User email / 用户邮箱
      username,    // Username / 用户名
      displayName  // Display name / 显示名称
    };
  }
  throw new Error('Invalid token');
}
```

#### Step 3: Backend Validation (Node.js Example) / 步骤3：后端验证 (Node.js 示例)

```javascript
// Express middleware for token validation / Express 中间件用于 token 验证
const axios = require('axios');

const LOGIN_SERVICE_URL = 'https://your-login-service.com';

async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  try {
    const response = await axios.post(`${LOGIN_SERVICE_URL}/api/auth/validate`, {
      token: token
    });
    
    if (response.data.success && response.data.data.valid) {
      // Attach user info to request / 将用户信息附加到请求
      req.user = {
        id: response.data.data.user.id,           // Unique ID / 唯一 ID
        email: response.data.data.user.email,
        username: response.data.data.user.username,
        displayName: response.data.data.user.display_name,
        isAdmin: response.data.data.user.is_admin
      };
      return next();
    }
    
    return res.status(401).json({ error: 'Invalid token' });
  } catch (error) {
    return res.status(401).json({ error: 'Token validation failed' });
  }
}

// Usage example / 使用示例
app.get('/api/my-protected-route', authMiddleware, (req, res) => {
  // Access user unique ID / 访问用户唯一 ID
  const userId = req.user.id;
  res.json({ 
    message: 'Hello!',
    userId: userId,
    email: req.user.email 
  });
});
```

#### Step 4: Backend Validation (Python Example) / 步骤4：后端验证 (Python 示例)

```python
import requests
from functools import wraps
from flask import request, jsonify

LOGIN_SERVICE_URL = 'https://your-login-service.com'

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            response = requests.post(
                f'{LOGIN_SERVICE_URL}/api/auth/validate',
                json={'token': token}
            )
            data = response.json()
            
            if data.get('success') and data.get('data', {}).get('valid'):
                # Get user info / 获取用户信息
                user = data['data']['user']
                request.user = {
                    'id': user['id'],                    # Unique ID / 唯一 ID
                    'email': user['email'],
                    'username': user['username'],
                    'display_name': user['display_name'],
                    'is_admin': user['is_admin']
                }
                return f(*args, **kwargs)
            
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'error': 'Token validation failed'}), 401
    
    return decorated

# Usage example / 使用示例
@app.route('/api/my-protected-route')
@require_auth
def protected_route():
    # Access user unique ID / 访问用户唯一 ID
    user_id = request.user['id']
    return jsonify({
        'message': 'Hello!',
        'userId': user_id,
        'email': request.user['email']
    })
```

#### Step 5: Backend Validation (Go Example) / 步骤5：后端验证 (Go 示例)

```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
    "strings"
)

const loginServiceURL = "https://your-login-service.com"

type ValidateResponse struct {
    Success bool `json:"success"`
    Data    struct {
        Valid bool `json:"valid"`
        User  struct {
            ID          uint   `json:"id"`           // Unique user ID / 用户唯一 ID
            Email       string `json:"email"`
            Username    string `json:"username"`
            DisplayName string `json:"display_name"`
            IsAdmin     bool   `json:"is_admin"`
        } `json:"user"`
    } `json:"data"`
}

func ValidateToken(token string) (*ValidateResponse, error) {
    reqBody, _ := json.Marshal(map[string]string{"token": token})
    
    resp, err := http.Post(
        loginServiceURL+"/api/auth/validate",
        "application/json",
        bytes.NewBuffer(reqBody),
    )
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result ValidateResponse
    json.NewDecoder(resp.Body).Decode(&result)
    return &result, nil
}

// Middleware example / 中间件示例
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        token := strings.TrimPrefix(authHeader, "Bearer ")
        
        result, err := ValidateToken(token)
        if err != nil || !result.Success || !result.Data.Valid {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        
        // User unique ID available in result.Data.User.ID
        // 用户唯一 ID 可通过 result.Data.User.ID 获取
        // Pass to next handler via context if needed
        next.ServeHTTP(w, r)
    })
}
```

### API Response Structure / API 响应结构

#### Validate Token Response / 验证 Token 响应

```json
{
  "success": true,
  "data": {
    "valid": true,
    "user": {
      "id": 123,                        // Unique user ID / 用户唯一 ID
      "email": "user@example.com",
      "username": "john_doe",
      "display_name": "John Doe",
      "avatar": "https://...",
      "balance": 100.50,                // User balance / 用户余额
      "vip_level": 3,                   // VIP level (0 = normal user) / VIP等级（0为普通用户）
      "is_active": true,
      "is_admin": false,
      "created_at": "2024-01-01T00:00:00Z",
      "last_login_at": "2024-01-15T10:30:00Z"
    }
  }
}
```

### Key Points / 关键要点

| Field | Description | 说明 |
|-------|-------------|------|
| `user.id` | **Unique user identifier** | **用户唯一标识符** |
| `user.email` | User's email address | 用户邮箱地址 |
| `user.username` | Unique username | 唯一用户名 |
| `user.display_name` | User's display name | 用户显示名称 |
| `user.balance` | User's account balance | 用户账户余额 |
| `user.vip_level` | User's VIP level (0 = normal) | 用户VIP等级（0为普通用户） |
| `user.is_admin` | Admin status | 管理员状态 |

### Security Best Practices / 安全最佳实践

1. **Always validate tokens on the backend** - Never trust client-side validation alone
   
   **始终在后端验证 token** - 不要仅依赖客户端验证

2. **Use HTTPS** - Always use HTTPS for token transmission
   
   **使用 HTTPS** - 始终使用 HTTPS 传输 token

3. **Token expiration** - Tokens expire based on JWT settings (default 24 hours)
   
   **Token 过期** - Token 根据 JWT 设置过期（默认 24 小时）

4. **Store tokens securely** - Use httpOnly cookies or secure storage
   
   **安全存储 token** - 使用 httpOnly cookie 或安全存储

### Simplified Integration with HMAC Signed URLs / 简化集成：HMAC 签名URL方式

For simpler integrations that don't require continuous token validation, you can use HMAC-signed callback URLs. After login, user information (UID, VIP level, balance) is passed directly via URL parameters with a tamper-proof signature.

对于不需要持续验证token的简单集成场景，可以使用HMAC签名回调URL。登录后，用户信息（UID、VIP等级、余额）通过URL参数直接传递，并附带防篡改签名。

#### Configuration / 配置

Add to `config.json`:

在 `config.json` 中添加：

```json
{
  "signed_url": {
    "enabled": true,
    "secret": "your-hmac-secret-key-at-least-32-chars",
    "expire_seconds": 300
  }
}
```

Or set environment variable / 或设置环境变量: `SIGNED_URL_SECRET`

#### Integration Flow / 集成流程

The integration flow works as follows:

集成流程如下：

1. User visits your application and clicks "Login" / 用户访问您的应用并点击"登录"
2. Your application redirects user to the login service / 您的应用将用户重定向到登录服务
3. User logs in successfully on the login service / 用户在登录服务上成功登录
4. Login service redirects user back to your callback URL with signed parameters / 登录服务将用户重定向回您的回调URL，附带签名参数
5. Your application verifies the signature and extracts user info / 您的应用验证签名并提取用户信息

#### Python Example: Local Signature Generation and Verification / Python示例：本地签名生成与验证

```python
import hmac
import hashlib
import time
from urllib.parse import urlencode, urlparse, parse_qs
from flask import Flask, request, redirect, jsonify

app = Flask(__name__)

# Configuration / 配置
HMAC_SECRET = 'your-hmac-secret-key-at-least-32-chars'  # Must match login service / 必须与登录服务一致
EXPIRE_SECONDS = 300
LOGIN_SERVICE_URL = 'https://your-login-service.com'

def generate_signature(uid: int, vip_level: int, balance: float, ts: int) -> str:
    """
    Generate HMAC-SHA256 signature for user data.
    生成用户数据的HMAC-SHA256签名。
    
    Parameters are sorted alphabetically: balance, ts, uid, vip_level
    参数按字母顺序排序：balance, ts, uid, vip_level
    """
    # Format balance to 2 decimal places / 将余额格式化为2位小数
    balance_str = f'{balance:.2f}'
    
    # Build data string (sorted by key) / 构建数据字符串（按key排序）
    data = {
        'balance': balance_str,
        'ts': str(ts),
        'uid': str(uid),
        'vip_level': str(vip_level)
    }
    sorted_keys = sorted(data.keys())
    string_to_sign = '&'.join(f'{k}={data[k]}' for k in sorted_keys)
    
    # Generate HMAC-SHA256 / 生成 HMAC-SHA256
    signature = hmac.new(
        HMAC_SECRET.encode(),
        string_to_sign.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return signature

def build_signed_callback_url(callback_url: str, uid: int, vip_level: int, balance: float) -> str:
    """
    Build a signed callback URL with user data.
    构建带有用户数据的签名回调URL。
    """
    ts = int(time.time())
    signature = generate_signature(uid, vip_level, balance, ts)
    
    params = {
        'uid': uid,
        'vip_level': vip_level,
        'balance': f'{balance:.2f}',
        'ts': ts,
        'signature': signature
    }
    
    # Append parameters to callback URL / 将参数附加到回调URL
    separator = '&' if '?' in callback_url else '?'
    return f'{callback_url}{separator}{urlencode(params)}'

def verify_signature(query_params: dict) -> dict:
    """
    Verify the HMAC signature and return user data if valid.
    验证HMAC签名，如果有效则返回用户数据。
    """
    signature = query_params.get('signature')
    ts_str = query_params.get('ts')
    uid = query_params.get('uid')
    vip_level = query_params.get('vip_level')
    balance = query_params.get('balance')
    
    # Validate required parameters / 验证必需参数
    if not all([signature, ts_str, uid, vip_level, balance]):
        raise ValueError('Missing required parameters / 缺少必需参数')
    
    ts = int(ts_str)
    
    # Check expiration / 检查过期
    if time.time() - ts > EXPIRE_SECONDS:
        raise ValueError('Signature expired / 签名已过期')
    
    # Generate expected signature / 生成期望签名
    expected = generate_signature(int(uid), int(vip_level), float(balance), ts)
    
    # Verify using timing-safe comparison / 使用时序安全比较验证
    if not hmac.compare_digest(signature, expected):
        raise ValueError('Invalid signature / 签名无效')
    
    return {
        'uid': int(uid),
        'vip_level': int(vip_level),
        'balance': float(balance)
    }

# Route: Redirect user to login service / 路由：将用户重定向到登录服务
@app.route('/login')
def login():
    """
    Redirect user to the login service.
    将用户重定向到登录服务。
    """
    # Your callback URL that will receive the signed user data
    # 您的回调URL，将接收签名的用户数据
    callback_url = 'https://your-app.com/callback'
    
    # Redirect to login page with callback URL
    # 重定向到登录页面，附带回调URL
    login_url = f'{LOGIN_SERVICE_URL}/auth/login?redirect={callback_url}'
    return redirect(login_url)

# Route: Handle callback from login service / 路由：处理来自登录服务的回调
@app.route('/callback')
def callback():
    """
    Handle the signed callback from login service.
    处理来自登录服务的签名回调。
    """
    try:
        # Verify signature and get user data / 验证签名并获取用户数据
        user = verify_signature(request.args.to_dict())
        
        # User is verified! You can now:
        # 用户已验证！您现在可以：
        # - Create a session / 创建会话
        # - Store user info in database / 将用户信息存储到数据库
        # - Redirect to dashboard / 重定向到仪表板
        
        return jsonify({
            'success': True,
            'message': 'Login successful / 登录成功',
            'user': user
        })
    except ValueError as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 401

# Example: Generate signed URL locally (for testing)
# 示例：本地生成签名URL（用于测试）
if __name__ == '__main__':
    # Example: Generate a signed callback URL
    # 示例：生成签名回调URL
    test_url = build_signed_callback_url(
        callback_url='https://your-app.com/callback',
        uid=123,
        vip_level=2,
        balance=100.50
    )
    print(f'Generated signed URL / 生成的签名URL: {test_url}')
    
    # Example: Verify the generated URL
    # 示例：验证生成的URL
    parsed = urlparse(test_url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    try:
        user = verify_signature(params)
        print(f'Verified user / 已验证用户: {user}')
    except ValueError as e:
        print(f'Verification failed / 验证失败: {e}')
    
    # Run Flask app / 运行Flask应用
    app.run(host='0.0.0.0', port=5000, debug=True)
```

#### Signed URL Response Format / 签名URL响应格式

The generated callback URL includes these parameters:

生成的回调URL包含以下参数：

| Parameter | Description | 说明 |
|-----------|-------------|------|
| `uid` | User's unique ID | 用户唯一ID |
| `vip_level` | VIP level (0 = normal) | VIP等级（0为普通用户） |
| `balance` | Account balance | 账户余额 |
| `ts` | Unix timestamp | Unix时间戳 |
| `signature` | HMAC-SHA256 signature | HMAC-SHA256签名 |

Example URL / 示例URL:
```
https://your-app.com/callback?uid=123&vip_level=2&balance=100.50&ts=1703136000&signature=abc123def456...
```

#### Security Considerations / 安全注意事项

1. **Keep HMAC secret secure** - Never expose in frontend code
   
   **保护HMAC密钥** - 不要在前端代码中暴露

2. **Use short expiration** - Default 5 minutes prevents replay attacks
   
   **使用短过期时间** - 默认5分钟可防止重放攻击

3. **Verify timestamp** - Always check if signature has expired
   
   **验证时间戳** - 始终检查签名是否过期

4. **Use HTTPS** - Always use HTTPS for callback URLs
   
   **使用HTTPS** - 始终在回调URL中使用HTTPS

## Project Structure / 项目结构

```
Common-LoginService/
├── .github/
│   └── workflows/
│       └── build.yml           # GitHub Actions CI/CD
├── cmd/
│   └── main.go                 # Application entry point / 程序入口
├── config/
│   └── config.go               # Configuration management / 配置管理
├── docs/                       # Swagger documentation / Swagger 文档
│   ├── docs.go
│   ├── swagger.json
│   └── swagger.yaml
├── internal/
│   ├── handler/                # HTTP handlers / HTTP 处理器
│   │   ├── auth_handler.go
│   │   ├── google_auth_handler.go
│   │   └── admin_handler.go
│   ├── i18n/                   # Internationalization / 国际化
│   │   └── i18n.go
│   ├── middleware/             # Middleware / 中间件
│   │   └── auth.go
│   ├── model/                  # Data models / 数据模型
│   │   └── user.go
│   ├── repository/             # Data access layer / 数据访问层
│   │   ├── user_repository.go
│   │   ├── session_repository.go
│   │   └── config_repository.go
│   └── service/                # Business logic / 业务逻辑层
│       ├── auth_service.go
│       └── email_service.go
├── pkg/
│   └── utils/                  # Utility functions / 工具函数
│       ├── crypto.go
│       └── jwt.go
├── static/
│   ├── vendor/                 # Local CSS/JS libraries / 本地 CSS/JS 库
│   │   ├── bootstrap/
│   │   └── bootstrap-icons/
│   ├── css/
│   └── js/
├── templates/                  # HTML templates / HTML 模板
│   ├── auth/
│   └── admin/
├── go.mod
├── go.sum
└── README.md
```

## Build / 构建

### Manual Build / 手动构建

```bash
# Build for current platform / 为当前平台构建
go build -o login-service ./cmd/main.go

# Build for Windows x64 / 为 Windows x64 构建
GOOS=windows GOARCH=amd64 go build -o login-service.exe ./cmd/main.go

# Build for Linux x64 / 为 Linux x64 构建
GOOS=linux GOARCH=amd64 go build -o login-service ./cmd/main.go
```

### GitHub Actions / 自动构建

The project includes GitHub Actions workflow that automatically builds for:
- Windows x64
- Linux x64

项目包含 GitHub Actions 工作流，自动为以下平台构建：
- Windows x64
- Linux x64

## Configure Google OAuth / 配置 Google OAuth

1. Visit [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Set redirect URI: `http://your-domain/api/auth/google/callback`
6. Fill in Client ID and Client Secret in config

## Configure Gmail API / 配置 Gmail API

1. Enable Gmail API in Google Cloud Console
2. Create OAuth 2.0 credentials
3. Download credentials file as `credentials.json`
4. Authorization will be guided on first run

## Security Recommendations / 安全建议

- Change default admin password in production / 生产环境请修改默认管理员密码
- Use strong random JWT secret / 使用强随机 JWT 密钥
- Enable HTTPS / 启用 HTTPS
- Regularly backup database / 定期备份数据库

## License / 许可证

MIT License
