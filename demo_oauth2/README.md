# OAuth2 第三方应用示例 (OAuth2 Demo Third-Party Application)

这是一个使用标准 OAuth2 授权码流程（Authorization Code Flow）接入 Common Login Service 的示例应用。

## 与签名回调方式的区别

| 特性 | OAuth2 标准 | 签名回调 |
|------|------------|---------|
| 标准化程度 | RFC 6749 标准 | 自定义协议 |
| 第三方库支持 | 广泛支持 | 需自行实现 |
| 安全性 | 高（多重验证） | 高（HMAC签名） |
| 实现复杂度 | 中等 | 简单 |

## 配置方式

程序启动时会自动生成 `config.json` 配置文件，支持两种配置方式：

### 方式一：JSON 配置文件（推荐）

首次运行程序会自动生成 `config.json` 文件，编辑该文件配置必要参数：

```json
{
  "port": "8082",
  "login_url": "https://your-login-service.com",
  "client_id": "your-api-token-here"
}
```

| 字段 | 说明 | 必填 |
|------|------|------|
| `login_url` | 登录服务地址（OAuth2 服务器） | 是 |
| `client_id` | API令牌（从管理后台获取，作为 OAuth2 client_id） | 是 |
| `port` | 服务端口 | 否（默认 `8082`） |

### 方式二：环境变量

环境变量优先级高于配置文件：

| 变量名 | 说明 |
|--------|------|
| `LOGIN_URL` | 登录服务地址 |
| `CLIENT_ID` | API令牌（作为 OAuth2 client_id） |
| `PORT` | 服务端口 |

## 快速开始

### 1. 获取 Client ID (API 令牌)

1. 登录管理后台（如 `https://your-login-service.com/admin`）
2. 进入「API令牌管理」页面
3. 创建一个新的 API 令牌
4. 复制生成的令牌作为 `client_id`

### 2. 运行示例

**方式一：使用配置文件**

```bash
# 首次运行，自动生成 config.json
go run main.go

# 编辑 config.json 配置 login_url 和 client_id
# 再次运行
go run main.go
```

**方式二：使用环境变量**

```bash
LOGIN_URL=https://your-login-service.com \
CLIENT_ID=your-api-token-here \
go run main.go
```

### 3. 访问演示

打开浏览器访问 `http://localhost:8082`，点击"OAuth2 登录"按钮即可体验。

## OAuth2 授权码流程

```
1. 用户点击登录按钮
   └─> 生成 state 参数（防止 CSRF）
   └─> 重定向到 LOGIN_URL/oauth2/authorize?response_type=code&client_id=xxx&redirect_uri=xxx&state=xxx

2. 用户在登录服务完成登录并授权
   └─> 登录服务验证用户身份

3. 授权成功，重定向回调地址
   └─> YOUR_CALLBACK_URL?code=xxx&state=xxx

4. 用授权码换取访问令牌
   └─> POST LOGIN_URL/oauth2/token
       grant_type=authorization_code&code=xxx&client_id=xxx&redirect_uri=xxx

5. 获取用户信息
   └─> GET LOGIN_URL/oauth2/userinfo
       Authorization: Bearer ACCESS_TOKEN

6. 登录完成
```

## 核心代码说明

### 1. 发起 OAuth2 授权

```go
// 生成 state 防止 CSRF
state, _ := generateState()

// 构建授权 URL
authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s",
    config.LoginURL,
    url.QueryEscape(config.ClientID),
    url.QueryEscape(callbackURL),
    url.QueryEscape(state),
)

// 重定向用户到授权页面
http.Redirect(w, r, authURL, http.StatusFound)
```

### 2. 处理回调并换取令牌

```go
// 验证 state（防止 CSRF）
if !validateState(state) {
    renderError(w, "无效的 state")
    return
}

// 用授权码换取访问令牌
data := url.Values{}
data.Set("grant_type", "authorization_code")
data.Set("code", code)
data.Set("client_id", config.ClientID)
data.Set("redirect_uri", redirectURI)

resp, _ := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
```

### 3. 获取用户信息

```go
req, _ := http.NewRequest("GET", userInfoURL, nil)
req.Header.Set("Authorization", "Bearer "+accessToken)

resp, _ := http.DefaultClient.Do(req)
```

## 编译

```bash
# 编译当前平台
go build -o demo_oauth2 main.go

# 编译 Linux 版本
CGO_ENABLED=0 GOOS=linux go build -o demo_oauth2-linux main.go

# 编译 Windows 版本
CGO_ENABLED=0 GOOS=windows go build -o demo_oauth2.exe main.go
```

## OAuth2 端点说明

| 端点 | URL | 说明 |
|------|-----|------|
| 授权端点 | `/oauth2/authorize` | 用户授权入口 |
| 令牌端点 | `/oauth2/token` | 用授权码换取访问令牌 |
| 用户信息端点 | `/oauth2/userinfo` | 获取用户信息 |

## 安全注意事项

1. **使用 state 参数**：每次授权请求都应生成随机的 state 参数，防止 CSRF 攻击
2. **验证 state**：回调时必须验证 state 参数是否匹配
3. **保护 client_id**：虽然不如 client_secret 敏感，但仍建议妥善保管
4. **使用 HTTPS**：生产环境请确保所有通信使用 HTTPS
5. **令牌有效期**：访问令牌默认1小时有效，过期后需重新授权

## 许可证

与主项目相同 - Apache 2.0
