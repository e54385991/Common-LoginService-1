# 第三方应用示例 (Demo Third-Party Application)

这是一个极简的第三方应用示例，展示如何快速集成 Common Login Service 进行用户认证。

## 配置方式

程序启动时会自动生成 `config.json` 配置文件，支持两种配置方式：

### 方式一：JSON 配置文件（推荐）

首次运行程序会自动生成 `config.json` 文件，编辑该文件配置必要参数：

```json
{
  "port": "8081",
  "login_url": "https://your-login-service.com",
  "api_token": "your-api-token-here"
}
```

| 字段 | 说明 | 必填 |
|------|------|------|
| `login_url` | 登录服务地址 | 是 |
| `api_token` | API令牌（从管理后台获取） | 是 |
| `port` | 服务端口 | 否（默认 `8081`） |

### 方式二：环境变量

环境变量优先级高于配置文件：

| 变量名 | 说明 |
|--------|------|
| `LOGIN_URL` | 登录服务地址 |
| `API_TOKEN` | API令牌 |
| `PORT` | 服务端口 |

## 快速开始

### 1. 获取 API 令牌

1. 登录管理后台（如 `https://your-login-service.com/admin`）
2. 进入「API令牌管理」页面
3. 创建一个新的 API 令牌（需要 user 权限）
4. 复制生成的令牌

### 2. 运行示例

**方式一：使用配置文件**

```bash
# 首次运行，自动生成 config.json
go run main.go

# 编辑 config.json 配置 login_url 和 api_token
# 再次运行
go run main.go
```

**方式二：使用环境变量**

```bash
LOGIN_URL=https://your-login-service.com \
API_TOKEN=your-api-token-here \
go run main.go
```

### 3. 访问演示

打开浏览器访问 `http://localhost:8081`，点击"使用统一账号登录"按钮即可体验。

## 工作原理

```
1. 用户点击登录按钮
   └─> 跳转到 LOGIN_URL/auth/login?callback=YOUR_CALLBACK_URL

2. 用户在登录服务完成登录
   └─> 登录服务生成签名并回调

3. 回调携带参数（简化格式）
   └─> YOUR_CALLBACK_URL?uid=xxx&vip_level=xxx&balance=xxx&ts=xxx&signature=xxx

4. 验证签名
   └─> POST LOGIN_URL/api/auth/verify-signature (携带 X-API-Key 头)

5. 验证成功，用户登录
```

## 核心代码说明

### 发起登录

```go
// 跳转到登录系统
loginURL := fmt.Sprintf("%s/auth/login?callback=%s", config.LoginURL, url.QueryEscape(callbackURL))
http.Redirect(w, r, loginURL, http.StatusFound)
```

### 处理回调并验证签名

```go
// 从URL获取签名参数（简化格式）
uid := r.URL.Query().Get("uid")
vipLevel := r.URL.Query().Get("vip_level")
balance := r.URL.Query().Get("balance")
ts := r.URL.Query().Get("ts")
signature := r.URL.Query().Get("signature")

// 调用API验证签名
reqBody := map[string]string{
    "uid":       uid,
    "vip_level": vipLevel,
    "balance":   balance,
    "ts":        ts,
    "signature": signature,
}
req, _ := http.NewRequest("POST", loginURL+"/api/auth/verify-signature", jsonBody)
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-API-Key", apiToken)
```

## 编译

```bash
# 编译当前平台
go build -o demo main.go

# 编译 Linux 版本
CGO_ENABLED=0 GOOS=linux go build -o demo-linux main.go

# 编译 Windows 版本
CGO_ENABLED=0 GOOS=windows go build -o demo.exe main.go
```

## 注意事项

1. **保护 API 令牌**：API 令牌应保存在服务器端，配置文件不要提交到版本控制
2. **使用 HTTPS**：生产环境请确保所有通信使用 HTTPS
3. **签名有效期**：签名默认5分钟内有效，超时需重新登录

## 许可证

与主项目相同 - Apache 2.0
