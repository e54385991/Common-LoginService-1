package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

const configFileName = "config.json"

// Default configuration values
var defaultConfig = Config{
	Port:        "8082",
	LoginURL:    "",
	ClientID:    "",
}

// Config holds the application configuration
type Config struct {
	Port        string `json:"port"`         // Server port (optional, default 8082)
	LoginURL    string `json:"login_url"`    // Login service URL (OAuth2 server)
	ClientID    string `json:"client_id"`    // API token from the login service admin panel (used as client_id)
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
	Error       string `json:"error,omitempty"`
	ErrorDesc   string `json:"error_description,omitempty"`
}

// UserInfo represents the user information from OAuth2 userinfo endpoint
type UserInfo struct {
	Sub      string `json:"sub"`
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	VIPLevel int    `json:"vip_level"`
}

var (
	config       Config
	// Simple in-memory state store (use Redis in production)
	stateStore   = make(map[string]bool)
	stateMutex   sync.RWMutex
)

func main() {
	// Load configuration
	config = loadConfig()

	// Check required configuration
	if config.LoginURL == "" {
		log.Println("警告: login_url 未设置")
		log.Printf("请编辑 %s 文件，配置 login_url 参数", configFileName)
	}

	if config.ClientID == "" {
		log.Println("警告: client_id 未设置，OAuth2 授权将失败")
		log.Printf("请编辑 %s 文件，配置 client_id 参数（从管理后台 /admin/api-tokens 页面获取）", configFileName)
	}

	// Set up routes
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/logout", handleLogout)

	log.Printf("OAuth2 Demo 演示应用启动，端口: %s", config.Port)
	log.Printf("登录服务地址 (OAuth2 Server): %s", config.LoginURL)
	log.Printf("回调地址: http://localhost:%s/callback", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, nil))
}

// loadConfig loads configuration from JSON file and environment variables
func loadConfig() Config {
	cfg := defaultConfig

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

	// Override with environment variables
	if port := os.Getenv("PORT"); port != "" {
		cfg.Port = port
	}
	if loginURL := os.Getenv("LOGIN_URL"); loginURL != "" {
		cfg.LoginURL = loginURL
	}
	if clientID := os.Getenv("CLIENT_ID"); clientID != "" {
		cfg.ClientID = clientID
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

// generateState generates a random state string for CSRF protection
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := base64.URLEncoding.EncodeToString(b)
	
	// Store state
	stateMutex.Lock()
	stateStore[state] = true
	stateMutex.Unlock()
	
	return state, nil
}

// validateState validates and consumes a state string
func validateState(state string) bool {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	
	if _, exists := stateStore[state]; exists {
		delete(stateStore, state)
		return true
	}
	return false
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
	cookie, err := r.Cookie("oauth2_user")
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

// handleLogin initiates the OAuth2 authorization flow
func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Generate state for CSRF protection
	state, err := generateState()
	if err != nil {
		renderError(w, "生成 state 失败")
		return
	}

	// Get callback URL
	callbackURL := getCallbackURL(r)

	// Build OAuth2 authorization URL
	authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s",
		config.LoginURL,
		url.QueryEscape(config.ClientID),
		url.QueryEscape(callbackURL),
		url.QueryEscape(state),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback handles the OAuth2 callback
func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Check for error response
	if errCode := r.URL.Query().Get("error"); errCode != "" {
		errDesc := r.URL.Query().Get("error_description")
		renderError(w, fmt.Sprintf("授权失败: %s - %s", errCode, errDesc))
		return
	}

	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		renderError(w, "缺少授权码")
		return
	}

	// Validate state (CSRF protection)
	if !validateState(state) {
		renderError(w, "无效的 state 参数（可能是 CSRF 攻击）")
		return
	}

	// Exchange authorization code for access token
	callbackURL := getCallbackURL(r)
	tokenResp, err := exchangeCodeForToken(code, callbackURL)
	if err != nil {
		renderError(w, fmt.Sprintf("换取令牌失败: %v", err))
		return
	}

	if tokenResp.Error != "" {
		renderError(w, fmt.Sprintf("令牌错误: %s - %s", tokenResp.Error, tokenResp.ErrorDesc))
		return
	}

	// Use access token to get user info
	userInfo, err := getUserInfo(tokenResp.AccessToken)
	if err != nil {
		renderError(w, fmt.Sprintf("获取用户信息失败: %v", err))
		return
	}

	// Store user info in cookie
	userCookie := encodeUserCookie(userInfo)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_user",
		Value:    userCookie,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		MaxAge:   3600, // 1 hour
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

// exchangeCodeForToken exchanges the authorization code for an access token
func exchangeCodeForToken(code, redirectURI string) (*TokenResponse, error) {
	// Build request body
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", config.ClientID)
	data.Set("redirect_uri", redirectURI)

	// Make POST request to token endpoint
	tokenURL := fmt.Sprintf("%s/oauth2/token", config.LoginURL)
	resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("请求令牌端点失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v, body: %s", err, string(body))
	}

	return &tokenResp, nil
}

// getUserInfo retrieves user information using the access token
func getUserInfo(accessToken string) (*UserInfo, error) {
	// Make GET request to userinfo endpoint
	userInfoURL := fmt.Sprintf("%s/oauth2/userinfo", config.LoginURL)
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求用户信息失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("获取用户信息失败: %s, body: %s", resp.Status, string(body))
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("解析用户信息失败: %v", err)
	}

	return &userInfo, nil
}

// handleLogout clears the user session
func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth2_user",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecureRequest(r),
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// parseUserCookie parses user info from cookie
func parseUserCookie(value string) *UserInfo {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil
	}

	var user UserInfo
	if err := json.Unmarshal(decoded, &user); err != nil {
		return nil
	}

	return &user
}

// encodeUserCookie encodes user info to cookie value
func encodeUserCookie(user *UserInfo) string {
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
    <title>OAuth2 第三方应用示例</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #1a5276 0%, #2980b9 100%);
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
        .badge {
            display: inline-block;
            padding: 4px 12px;
            background: #e3f2fd;
            color: #1565c0;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 20px;
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
            background: linear-gradient(135deg, #1a5276 0%, #2980b9 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(26, 82, 118, 0.4);
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
            background: #e3f2fd;
            border-radius: 8px;
            font-size: 14px;
            color: #1565c0;
        }
        .oauth2-badge {
            background: #2196F3;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            margin-left: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="badge">OAuth2 标准协议</div>
        <h1>🔐 OAuth2 第三方应用示例</h1>
        <p class="subtitle">演示标准 OAuth2 授权码流程</p>
        
        {{if .User}}
        <div class="user-info">
            <h2>✅ 登录成功</h2>
            <div class="info-item">
                <span class="info-label">用户ID</span>
                <span class="info-value">{{.User.UserID}}</span>
            </div>
            <div class="info-item">
                <span class="info-label">用户名</span>
                <span class="info-value">{{.User.Username}}</span>
            </div>
            <div class="info-item">
                <span class="info-label">VIP等级</span>
                <span class="info-value vip">{{if gt .User.VIPLevel 0}}VIP {{.User.VIPLevel}}{{else}}普通用户{{end}}</span>
            </div>
        </div>
        <a href="/logout" class="btn btn-danger">退出登录</a>
        {{else}}
        <p class="login-prompt">点击下方按钮使用 OAuth2 标准流程登录</p>
        <a href="/login" class="btn btn-primary">🔐 OAuth2 登录<span class="oauth2-badge">标准</span></a>
        {{end}}
        
        <div class="note">
            💡 这是一个 OAuth2 第三方应用示例，展示标准 OAuth2 授权码流程（Authorization Code Flow）。
            <br><br>
            OAuth2 服务器地址：<strong>{{.LoginURL}}</strong>
        </div>
    </div>
</body>
</html>`

const errorTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>错误 - OAuth2 第三方应用示例</title>
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
            word-break: break-word;
        }
        .btn {
            display: inline-block;
            padding: 12px 30px;
            border-radius: 25px;
            font-size: 16px;
            font-weight: 600;
            text-decoration: none;
            background: linear-gradient(135deg, #1a5276 0%, #2980b9 100%);
            color: white;
            transition: all 0.3s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 20px rgba(26, 82, 118, 0.4);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>❌ OAuth2 授权失败</h1>
        <p class="message">{{.Message}}</p>
        <a href="/" class="btn">返回首页</a>
    </div>
</body>
</html>`
