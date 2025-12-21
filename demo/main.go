package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Config holds the application configuration
type Config struct {
	Port          string // Server port
	LoginURL      string // Login service URL (e.g., https://user.yuelk.com)
	CallbackURL   string // This demo's callback URL
	SignedSecret  string // Secret key for HMAC signature verification
	ExpireSeconds int64  // Maximum age for signed callbacks
}

// UserInfo represents the user information from signed callback
type UserInfo struct {
	UID      uint
	VIPLevel int
	Balance  float64
}

var config Config

func main() {
	// Load configuration from environment or use defaults
	config = Config{
		Port:          getEnv("PORT", "8081"),
		LoginURL:      getEnv("LOGIN_URL", "https://user.yuelk.com"),
		CallbackURL:   getEnv("CALLBACK_URL", "http://localhost:8081/callback"),
		SignedSecret:  getEnv("SIGNED_SECRET", "your-secret-key"), // Must match login service
		ExpireSeconds: getEnvInt("EXPIRE_SECONDS", 300),           // 5 minutes
	}

	// Set up routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)

	log.Printf("Demo third-party application starting on port %s", config.Port)
	log.Printf("Login URL: %s", config.LoginURL)
	log.Printf("Callback URL: %s", config.CallbackURL)
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// isSecureRequest checks if the request is over HTTPS
func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// handleHome renders the home page
func handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user is logged in via cookie
	cookie, err := r.Cookie("demo_user")
	var user *UserInfo
	if err == nil && cookie.Value != "" {
		user = parseUserCookie(cookie.Value)
	}

	tmpl := template.Must(template.New("home").Parse(homeTemplate))
	tmpl.Execute(w, map[string]interface{}{
		"LoginURL": config.LoginURL,
		"User":     user,
	})
}

// handleLogin initiates the OAuth-like flow
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect to the login service with redirect URL
	loginURL := fmt.Sprintf("%s/auth/login?redirect=%s", config.LoginURL, url.QueryEscape(config.CallbackURL))
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// handleCallback handles the signed callback from login service
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get parameters from query string
	uid := r.URL.Query().Get("uid")
	vipLevel := r.URL.Query().Get("vip_level")
	balance := r.URL.Query().Get("balance")
	ts := r.URL.Query().Get("ts")
	signature := r.URL.Query().Get("signature")

	// Validate required parameters
	if uid == "" || vipLevel == "" || balance == "" || ts == "" || signature == "" {
		renderError(w, "Missing required parameters")
		return
	}

	// Verify timestamp
	timestamp, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		renderError(w, "Invalid timestamp")
		return
	}

	if time.Now().Unix()-timestamp > config.ExpireSeconds {
		renderError(w, "Callback has expired")
		return
	}

	// Verify signature
	expectedSignature := generateSignature(uid, vipLevel, balance, ts)
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		renderError(w, "Invalid signature")
		return
	}

	// Parse user data with proper error handling
	uidInt, err := strconv.ParseUint(uid, 10, 64)
	if err != nil {
		renderError(w, "Invalid user ID")
		return
	}
	vipLevelInt, err := strconv.Atoi(vipLevel)
	if err != nil {
		renderError(w, "Invalid VIP level")
		return
	}
	balanceFloat, err := strconv.ParseFloat(balance, 64)
	if err != nil {
		renderError(w, "Invalid balance")
		return
	}

	// Store user info in cookie (in production, use secure session)
	userCookie := fmt.Sprintf("%d:%d:%.2f", uidInt, vipLevelInt, balanceFloat)
	http.SetCookie(w, &http.Cookie{
		Name:     "demo_user",
		Value:    userCookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		MaxAge:   3600, // 1 hour
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// handleLogout clears the user session
func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "demo_user",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// generateSignature generates HMAC signature for verification
func generateSignature(uid, vipLevel, balance, ts string) string {
	// Build the data string in the same format as the login service
	data := fmt.Sprintf("balance=%s&ts=%s&uid=%s&vip_level=%s", balance, ts, uid, vipLevel)
	h := hmac.New(sha256.New, []byte(config.SignedSecret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// parseUserCookie parses user info from cookie
func parseUserCookie(value string) *UserInfo {
	var uid uint64
	var vipLevel int
	var balance float64
	_, err := fmt.Sscanf(value, "%d:%d:%f", &uid, &vipLevel, &balance)
	if err != nil {
		return nil
	}
	return &UserInfo{
		UID:      uint(uid),
		VIPLevel: vipLevel,
		Balance:  balance,
	}
}

func renderError(w http.ResponseWriter, message string) {
	tmpl := template.Must(template.New("error").Parse(errorTemplate))
	w.WriteHeader(http.StatusBadRequest)
	tmpl.Execute(w, map[string]interface{}{
		"Message":  message,
		"LoginURL": config.LoginURL,
	})
}

// HTML Templates
const homeTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>第三方示例应用</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 90%;
            text-align: center;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
        }
        .user-info {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .user-info h2 {
            color: #28a745;
            margin-bottom: 15px;
        }
        .info-item {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #eee;
        }
        .info-item:last-child {
            border-bottom: none;
        }
        .info-label {
            color: #666;
        }
        .info-value {
            font-weight: bold;
            color: #333;
        }
        .info-value.vip {
            color: #ffc107;
        }
        .info-value.balance {
            color: #28a745;
        }
        .btn {
            display: inline-block;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 16px;
            font-weight: 600;
            text-decoration: none;
            cursor: pointer;
            border: none;
            transition: all 0.3s;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .login-prompt {
            color: #666;
            margin-bottom: 20px;
        }
        .note {
            margin-top: 20px;
            padding: 15px;
            background: #e7f3ff;
            border-radius: 8px;
            font-size: 14px;
            color: #0066cc;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔗 第三方示例应用</h1>
        <p class="subtitle">演示如何集成 Common Login Service</p>
        
        {{if .User}}
        <div class="user-info">
            <h2>✅ 登录成功</h2>
            <div class="info-item">
                <span class="info-label">用户ID</span>
                <span class="info-value">{{.User.UID}}</span>
            </div>
            <div class="info-item">
                <span class="info-label">VIP等级</span>
                <span class="info-value vip">{{if gt .User.VIPLevel 0}}VIP {{.User.VIPLevel}}{{else}}普通用户{{end}}</span>
            </div>
            <div class="info-item">
                <span class="info-label">账户余额</span>
                <span class="info-value balance">¥{{printf "%.2f" .User.Balance}}</span>
            </div>
        </div>
        <a href="/logout" class="btn btn-danger">退出登录</a>
        {{else}}
        <p class="login-prompt">点击下方按钮使用 Common Login Service 登录</p>
        <a href="/login" class="btn btn-primary">🔐 使用统一账号登录</a>
        {{end}}
        
        <div class="note">
            💡 这是一个简单的第三方应用示例，展示如何使用签名回调URL进行用户认证。
            <br><br>
            登录服务地址：<strong>{{.LoginURL}}</strong>
        </div>
    </div>
</body>
</html>`

const errorTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>错误 - 第三方示例应用</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.2);
            max-width: 500px;
            width: 90%;
            text-align: center;
        }
        h1 {
            color: #e74c3c;
            margin-bottom: 20px;
        }
        .message {
            color: #666;
            margin-bottom: 30px;
        }
        .btn {
            display: inline-block;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 16px;
            font-weight: 600;
            text-decoration: none;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            transition: all 0.3s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ 认证失败</h1>
        <p class="message">{{.Message}}</p>
        <a href="/" class="btn">返回首页</a>
    </div>
</body>
</html>`
