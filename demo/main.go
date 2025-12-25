package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
)

const configFileName = "config.json"

// Default configuration values
var defaultConfig = Config{
	Port:     "8081",
	LoginURL: "",
	APIToken: "",
}

// Config holds the application configuration
// 只需要配置2个参数：远程服务地址和API令牌
type Config struct {
	Port     string `json:"port"`      // Server port (optional, default 8081)
	LoginURL string `json:"login_url"` // Login service URL
	APIToken string `json:"api_token"` // API token from the login service admin panel
}

// UserInfo represents the user information from signed callback
type UserInfo struct {
	UserID   uint    `json:"user_id"`
	VIPLevel int     `json:"vip_level"`
	Balance  float64 `json:"balance"`
}

var config Config

func main() {
	// 加载配置：优先使用环境变量，其次使用配置文件
	config = loadConfig()

	// 检查必要配置
	if config.LoginURL == "" {
		log.Println("警告: login_url 未设置")
		log.Printf("请编辑 %s 文件，配置 login_url 参数", configFileName)
	}

	if config.APIToken == "" {
		log.Println("警告: api_token 未设置，签名验证将失败")
		log.Printf("请编辑 %s 文件，配置 api_token 参数（从管理后台 /admin/api-tokens 页面获取）", configFileName)
	}

	// Set up routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)

	log.Printf("Demo 演示应用启动，端口: %s", config.Port)
	log.Printf("登录服务地址: %s", config.LoginURL)
	log.Printf("回调地址: http://localhost:%s/callback", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

// loadConfig loads configuration from JSON file and environment variables
// Environment variables take precedence over JSON file settings
func loadConfig() Config {
	cfg := defaultConfig // Start with defaults

	// Try to load from JSON file
	if data, err := os.ReadFile(configFileName); err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Printf("警告: 解析配置文件 %s 失败: %v", configFileName, err)
		} else {
			log.Printf("已从 %s 加载配置", configFileName)
		}
	} else if os.IsNotExist(err) {
		// Generate default config file if it doesn't exist
		if err := generateDefaultConfig(); err != nil {
			log.Printf("警告: 生成默认配置文件失败: %v", err)
		} else {
			log.Printf("已生成默认配置文件 %s，请编辑该文件配置必要参数", configFileName)
		}
	}

	// Override with environment variables (env vars take precedence)
	if port := os.Getenv("PORT"); port != "" {
		cfg.Port = port
	}
	if loginURL := os.Getenv("LOGIN_URL"); loginURL != "" {
		cfg.LoginURL = loginURL
	}
	if apiToken := os.Getenv("API_TOKEN"); apiToken != "" {
		cfg.APIToken = apiToken
	}

	return cfg
}

// generateDefaultConfig generates a default config.json file
func generateDefaultConfig() error {
	data, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFileName, data, 0600)
}

// getCallbackURL returns the callback URL for this demo
func getCallbackURL(r *http.Request) string {
	// Try to auto-detect callback URL from request
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:" + config.Port
	}
	return fmt.Sprintf("%s://%s/callback", scheme, host)
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

// handleLogin initiates the login flow - 跳转到登录系统
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// 获取回调地址
	callbackURL := getCallbackURL(r)
	
	// 构建登录URL：/auth/login?callback=YOUR_CALLBACK_URL
	loginURL := fmt.Sprintf("%s/auth/login?callback=%s", config.LoginURL, url.QueryEscape(callbackURL))
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// handleCallback handles the signed callback from login service
// 回调参数：uid, vip_level, balance, ts, signature
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// 从URL参数获取签名信息 (简化格式: uid, vip_level, balance, ts, signature)
	uid := r.URL.Query().Get("uid")
	vipLevel := r.URL.Query().Get("vip_level")
	balance := r.URL.Query().Get("balance")
	ts := r.URL.Query().Get("ts")
	signature := r.URL.Query().Get("signature")

	// 验证必要参数
	if uid == "" || vipLevel == "" || balance == "" || ts == "" || signature == "" {
		renderError(w, "缺少必要参数")
		return
	}

	// 调用远程API验证签名
	verified, verifiedVIPLevel, verifiedBalance, err := verifySignature(uid, vipLevel, balance, ts, signature)
	if err != nil {
		renderError(w, fmt.Sprintf("验证失败: %v", err))
		return
	}
	if !verified {
		renderError(w, "签名验证失败")
		return
	}

	// Store user info in cookie (base64 encoded JSON)
	userCookie := encodeUserCookie(uid, verifiedVIPLevel, verifiedBalance)
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

// verifySignature 调用远程API验证签名
func verifySignature(uid, vipLevel, balance, ts, signature string) (bool, int, float64, error) {
	// 构建验证请求 (简化格式: uid, vip_level, balance, ts, signature)
	verifyURL := fmt.Sprintf("%s/api/auth/verify-signature", config.LoginURL)
	
	reqBody := map[string]string{
		"uid":       uid,
		"vip_level": vipLevel,
		"balance":   balance,
		"ts":        ts,
		"signature": signature,
	}
	
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return false, 0, 0, err
	}

	// 发送POST请求
	req, err := http.NewRequest("POST", verifyURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, 0, 0, err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", config.APIToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, 0, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, 0, 0, err
	}

	// 解析响应
	var result struct {
		Success bool `json:"success"`
		Data    struct {
			Valid    bool    `json:"valid"`
			UID      uint    `json:"uid"`
			VIPLevel int     `json:"vip_level"`
			Balance  float64 `json:"balance"`
			Message  string  `json:"message"`
		} `json:"data"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return false, 0, 0, fmt.Errorf("解析响应失败: %v", err)
	}

	if !result.Success {
		return false, 0, 0, fmt.Errorf("%s", result.Message)
	}

	if !result.Data.Valid {
		if result.Data.Message != "" {
			return false, 0, 0, fmt.Errorf("%s", result.Data.Message)
		}
		return false, 0, 0, nil
	}

	return true, result.Data.VIPLevel, result.Data.Balance, nil
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

// parseUserCookie parses user info from cookie (base64 encoded JSON)
func parseUserCookie(value string) *UserInfo {
	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil
	}
	
	// Parse JSON
	var user UserInfo
	if err := json.Unmarshal(decoded, &user); err != nil {
		return nil
	}
	
	return &user
}

// encodeUserCookie encodes user info to cookie value (base64 encoded JSON)
func encodeUserCookie(userID string, vipLevel int, balance float64) string {
	var uid uint
	fmt.Sscanf(userID, "%d", &uid)
	
	user := UserInfo{
		UserID:   uid,
		VIPLevel: vipLevel,
		Balance:  balance,
	}
	
	jsonData, err := json.Marshal(user)
	if err != nil {
		return ""
	}
	
	return base64.StdEncoding.EncodeToString(jsonData)
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
                <span class="info-value">{{.User.UserID}}</span>
            </div>
            <div class="info-item">
                <span class="info-label">余额</span>
                <span class="info-value balance">¥{{printf "%.2f" .User.Balance}}</span>
            </div>
            <div class="info-item">
                <span class="info-label">VIP等级</span>
                <span class="info-value vip">{{if gt .User.VIPLevel 0}}VIP {{.User.VIPLevel}}{{else}}普通用户{{end}}</span>
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
