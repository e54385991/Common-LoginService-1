package i18n

import (
	"strings"
	"sync"
)

// Translations holds all translations
var translations = map[string]map[string]string{
	"en": {
		// Common
		"app.name":        "Common Login Service",
		"app.title":       "Unified Authentication Service",
		"app.description": "Secure and convenient user authentication solution. Supports multiple login methods, easily integrates into your system.",

		// Navigation
		"nav.home":     "Home",
		"nav.login":    "Login",
		"nav.register": "Register",
		"nav.logout":   "Logout",
		"nav.profile":  "Profile",

		// Auth - Login
		"login.title":           "Login",
		"login.subtitle":        "Welcome back, please login to your account",
		"login.email":           "Email",
		"login.email.placeholder": "Enter your email",
		"login.password":        "Password",
		"login.password.placeholder": "Enter your password",
		"login.remember":        "Remember me",
		"login.forgot":          "Forgot password?",
		"login.submit":          "Login",
		"login.google":          "Login with Google",
		"login.no_account":      "Don't have an account?",
		"login.register_now":    "Register now",
		"login.success":         "Login successful",
		"login.error":           "Invalid email or password",
		"login.network_error":   "Network error, please try again later",

		// Auth - Register
		"register.title":           "Register",
		"register.subtitle":        "Create your account to get started",
		"register.email":           "Email",
		"register.email.placeholder": "Enter your email",
		"register.username":        "Username",
		"register.username.placeholder": "3-30 characters, letters, numbers, underscore",
		"register.display_name":    "Display Name",
		"register.display_name.placeholder": "The name you want to display",
		"register.display_name.optional": "(Optional)",
		"register.password":        "Password",
		"register.password.placeholder": "At least 6 characters",
		"register.confirm_password": "Confirm Password",
		"register.confirm_password.placeholder": "Enter password again",
		"register.agree":           "I agree to the",
		"register.terms":           "Terms of Service",
		"register.and":             "and",
		"register.privacy":         "Privacy Policy",
		"register.submit":          "Register",
		"register.google":          "Register with Google",
		"register.has_account":     "Already have an account?",
		"register.login_now":       "Login now",
		"register.success":         "Registration successful",
		"register.password_mismatch": "Passwords do not match",

		// Auth - Forgot Password
		"forgot.title":      "Forgot Password",
		"forgot.subtitle":   "Enter your email, we will send you a reset link",
		"forgot.email":      "Email",
		"forgot.email.placeholder": "Enter the email you registered with",
		"forgot.submit":     "Send Reset Link",
		"forgot.back":       "Back to Login",
		"forgot.success":    "If this email is registered, you will receive a password reset email",

		// Auth - Reset Password
		"reset.title":       "Reset Password",
		"reset.subtitle":    "Please enter your new password",
		"reset.password":    "New Password",
		"reset.password.placeholder": "At least 6 characters",
		"reset.confirm":     "Confirm New Password",
		"reset.confirm.placeholder": "Enter new password again",
		"reset.submit":      "Reset Password",
		"reset.back":        "Back to Login",
		"reset.success":     "Password reset successful, please login again",

		// Home Page
		"home.hero.title":       "Unified Authentication Service",
		"home.hero.description": "Secure and convenient user authentication solution. Supports multiple login methods, easily integrates into your system.",
		"home.hero.start":       "Get Started",
		"home.hero.learn":       "Learn More",
		"home.welcome":          "Welcome back",
		"home.features.title":   "Core Features",
		"home.feature.google":   "Google Login",
		"home.feature.google.desc": "Support Google OAuth one-click login, improve user experience",
		"home.feature.email":    "Email Recovery",
		"home.feature.email.desc": "Send password reset emails via Gmail API, secure and reliable",
		"home.feature.api":      "API Integration",
		"home.feature.api.desc": "Standard RESTful API, easily integrate with various systems",
		"home.feature.jwt":      "JWT Authentication",
		"home.feature.jwt.desc": "Use JWT Token for authentication, stateless design",
		"home.feature.admin":    "Admin Backend",
		"home.feature.admin.desc": "Powerful admin system, configure various parameters",
		"home.feature.security": "Secure Storage",
		"home.feature.security.desc": "Passwords encrypted with bcrypt, ensure user data security",
		"home.api.title":        "API Endpoints",
		"home.api.register":     "Register",
		"home.api.login":        "Login",
		"home.api.logout":       "Logout",
		"home.api.profile":      "Get User Info",
		"home.api.validate":     "Validate Token",
		"home.api.forgot":       "Forgot Password",
		"home.api.reset":        "Reset Password",
		"home.footer":           "All rights reserved.",

		// Profile
		"profile.title":      "Profile",
		"profile.close":      "Close",
		"profile.registered": "Registered on",

		// Admin
		"admin.title":       "Admin Panel",
		"admin.login.title": "Admin Login",
		"admin.login.subtitle": "Please login with admin account",
		"admin.username":    "Username",
		"admin.username.placeholder": "Enter admin username",
		"admin.password":    "Password",
		"admin.password.placeholder": "Enter admin password",
		"admin.login":       "Login",
		"admin.back":        "Back to Home",
		"admin.dashboard":   "Dashboard",
		"admin.users":       "User Management",
		"admin.settings":    "System Settings",
		"admin.logout":      "Logout",
		"admin.user_count":  "Registered Users",
		"admin.status":      "System Status",
		"admin.running":     "Running",
		"admin.framework":   "Framework",
		"admin.sysinfo":     "System Info",
		"admin.version":     "Framework Version",
		"admin.go_version":  "Go Version",
		"admin.database":    "Database",
		"admin.auth_method": "Auth Method",
		"admin.quick_actions": "Quick Actions",
		"admin.visit_frontend": "Visit Frontend",
		"admin.google_oauth": "Google OAuth Settings",
		"admin.gmail_api":   "Gmail API Settings",
		"admin.jwt_settings": "JWT Settings",
		"admin.enabled":     "Enabled",
		"admin.client_id":   "Client ID",
		"admin.client_secret": "Client Secret",
		"admin.redirect_url": "Redirect URL",
		"admin.save":        "Save",
		"admin.sender_email": "Sender Email",
		"admin.gmail_note":  "Gmail API requires OAuth 2.0 credentials file. Please place credentials.json in the project root.",
		"admin.token_expire": "Token Expiry (hours)",
		"admin.jwt_secret":  "JWT Secret",
		"admin.user_list":   "User List",
		"admin.total":       "Total",
		"admin.id":          "ID",
		"admin.email":       "Email",
		"admin.display_name": "Display Name",
		"admin.status_col":  "Status",
		"admin.created_at":  "Registered At",
		"admin.actions":     "Actions",
		"admin.active":      "Active",
		"admin.disabled":    "Disabled",
		"admin.is_admin":    "Admin",
		"admin.no_users":    "No user data",

		// Captcha
		"captcha.title":       "Security Verification",
		"captcha.drag_hint":   "Drag the slider to the target",
		"captcha.slide_hint":  "Slide to verify",
		"captcha.success":     "Verification successful",
		"captcha.failed":      "Verification failed, please try again",
		"captcha.required":    "Please complete the captcha verification",

		// Errors
		"error.invalid_email":     "Invalid email address",
		"error.invalid_username":  "Username can only contain letters, numbers and underscores, 3-30 characters",
		"error.invalid_password":  "Password must be at least 6 characters",
		"error.email_exists":      "Email already registered",
		"error.username_exists":   "Username already taken",
		"error.user_not_found":    "User not found",
		"error.account_disabled":  "Account has been disabled",
		"error.invalid_token":     "Invalid token",
		"error.token_expired":     "Token has expired",
	},
	"zh": {
		// Common
		"app.name":        "Common Login Service",
		"app.title":       "统一身份认证服务",
		"app.description": "安全、便捷的用户认证解决方案。支持多种登录方式，轻松集成到您的系统中。",

		// Navigation
		"nav.home":     "首页",
		"nav.login":    "登录",
		"nav.register": "注册",
		"nav.logout":   "退出登录",
		"nav.profile":  "个人资料",

		// Auth - Login
		"login.title":           "登录",
		"login.subtitle":        "欢迎回来，请登录您的账户",
		"login.email":           "邮箱",
		"login.email.placeholder": "请输入邮箱",
		"login.password":        "密码",
		"login.password.placeholder": "请输入密码",
		"login.remember":        "记住我",
		"login.forgot":          "忘记密码？",
		"login.submit":          "登录",
		"login.google":          "使用 Google 账号登录",
		"login.no_account":      "还没有账户？",
		"login.register_now":    "立即注册",
		"login.success":         "登录成功",
		"login.error":           "邮箱或密码错误",
		"login.network_error":   "网络错误，请稍后重试",

		// Auth - Register
		"register.title":           "注册",
		"register.subtitle":        "创建您的账户，开始使用",
		"register.email":           "邮箱",
		"register.email.placeholder": "请输入邮箱",
		"register.username":        "用户名",
		"register.username.placeholder": "3-30个字符，字母数字下划线",
		"register.display_name":    "显示名称",
		"register.display_name.placeholder": "您希望显示的名称",
		"register.display_name.optional": "(可选)",
		"register.password":        "密码",
		"register.password.placeholder": "至少6个字符",
		"register.confirm_password": "确认密码",
		"register.confirm_password.placeholder": "请再次输入密码",
		"register.agree":           "我同意",
		"register.terms":           "服务条款",
		"register.and":             "和",
		"register.privacy":         "隐私政策",
		"register.submit":          "注册",
		"register.google":          "使用 Google 账号注册",
		"register.has_account":     "已有账户？",
		"register.login_now":       "立即登录",
		"register.success":         "注册成功",
		"register.password_mismatch": "两次输入的密码不一致",

		// Auth - Forgot Password
		"forgot.title":      "忘记密码",
		"forgot.subtitle":   "输入您的邮箱，我们将发送重置链接",
		"forgot.email":      "邮箱",
		"forgot.email.placeholder": "请输入注册时使用的邮箱",
		"forgot.submit":     "发送重置链接",
		"forgot.back":       "返回登录",
		"forgot.success":    "如果该邮箱已注册，您将收到重置密码的邮件",

		// Auth - Reset Password
		"reset.title":       "重置密码",
		"reset.subtitle":    "请输入您的新密码",
		"reset.password":    "新密码",
		"reset.password.placeholder": "至少6个字符",
		"reset.confirm":     "确认新密码",
		"reset.confirm.placeholder": "请再次输入新密码",
		"reset.submit":      "重置密码",
		"reset.back":        "返回登录",
		"reset.success":     "密码重置成功，请重新登录",

		// Home Page
		"home.hero.title":       "统一身份认证服务",
		"home.hero.description": "安全、便捷的用户认证解决方案。支持多种登录方式，轻松集成到您的系统中。",
		"home.hero.start":       "开始使用",
		"home.hero.learn":       "了解更多",
		"home.welcome":          "欢迎回来",
		"home.features.title":   "核心功能",
		"home.feature.google":   "Google 登录",
		"home.feature.google.desc": "支持 Google OAuth 一键登录，提升用户体验",
		"home.feature.email":    "邮件找回",
		"home.feature.email.desc": "通过 Gmail API 发送密码重置邮件，安全可靠",
		"home.feature.api":      "API 集成",
		"home.feature.api.desc": "标准 RESTful API，轻松对接各类系统",
		"home.feature.jwt":      "JWT 认证",
		"home.feature.jwt.desc": "使用 JWT Token 进行身份验证，无状态设计",
		"home.feature.admin":    "后台管理",
		"home.feature.admin.desc": "强大的后台管理系统，配置各项参数",
		"home.feature.security": "安全存储",
		"home.feature.security.desc": "密码采用 bcrypt 加密，保障用户数据安全",
		"home.api.title":        "API 接口",
		"home.api.register":     "注册",
		"home.api.login":        "登录",
		"home.api.logout":       "登出",
		"home.api.profile":      "获取用户信息",
		"home.api.validate":     "验证 Token",
		"home.api.forgot":       "忘记密码",
		"home.api.reset":        "重置密码",
		"home.footer":           "版权所有。",

		// Profile
		"profile.title":      "个人资料",
		"profile.close":      "关闭",
		"profile.registered": "注册于",

		// Admin
		"admin.title":       "管理后台",
		"admin.login.title": "管理后台",
		"admin.login.subtitle": "请登录管理员账户",
		"admin.username":    "用户名",
		"admin.username.placeholder": "请输入管理员用户名",
		"admin.password":    "密码",
		"admin.password.placeholder": "请输入管理员密码",
		"admin.login":       "登录",
		"admin.back":        "返回首页",
		"admin.dashboard":   "控制面板",
		"admin.users":       "用户管理",
		"admin.settings":    "系统设置",
		"admin.logout":      "退出登录",
		"admin.user_count":  "注册用户",
		"admin.status":      "系统状态",
		"admin.running":     "运行中",
		"admin.framework":   "运行框架",
		"admin.sysinfo":     "系统信息",
		"admin.version":     "框架版本",
		"admin.go_version":  "Go 版本",
		"admin.database":    "数据库",
		"admin.auth_method": "认证方式",
		"admin.quick_actions": "快捷操作",
		"admin.visit_frontend": "访问前台",
		"admin.google_oauth": "Google OAuth 设置",
		"admin.gmail_api":   "Gmail API 设置",
		"admin.jwt_settings": "JWT 设置",
		"admin.enabled":     "启用",
		"admin.client_id":   "Client ID",
		"admin.client_secret": "Client Secret",
		"admin.redirect_url": "Redirect URL",
		"admin.save":        "保存",
		"admin.sender_email": "发送邮箱",
		"admin.gmail_note":  "Gmail API 需要配置 OAuth 2.0 凭据文件。请将 credentials.json 放置在项目根目录。",
		"admin.token_expire": "Token 有效期（小时）",
		"admin.jwt_secret":  "JWT Secret",
		"admin.user_list":   "用户列表",
		"admin.total":       "共",
		"admin.id":          "ID",
		"admin.email":       "邮箱",
		"admin.display_name": "显示名称",
		"admin.status_col":  "状态",
		"admin.created_at":  "注册时间",
		"admin.actions":     "操作",
		"admin.active":      "正常",
		"admin.disabled":    "禁用",
		"admin.is_admin":    "管理员",
		"admin.no_users":    "暂无用户数据",

		// Captcha
		"captcha.title":       "安全验证",
		"captcha.drag_hint":   "请拖动滑块到指定位置",
		"captcha.slide_hint":  "拖动滑块验证",
		"captcha.success":     "验证成功",
		"captcha.failed":      "验证失败，请重试",
		"captcha.required":    "请先完成验证码验证",

		// Errors
		"error.invalid_email":     "无效的邮箱地址",
		"error.invalid_username":  "用户名只能包含字母、数字和下划线，长度3-30个字符",
		"error.invalid_password":  "密码长度至少6个字符",
		"error.email_exists":      "邮箱已被注册",
		"error.username_exists":   "用户名已被使用",
		"error.user_not_found":    "用户不存在",
		"error.account_disabled":  "账户已被禁用",
		"error.invalid_token":     "无效的令牌",
		"error.token_expired":     "重置令牌已过期",
	},
}

var (
	defaultLang = "en"
	mu          sync.RWMutex
)

// Init initializes the i18n system
func Init() {
	// Initialize with default translations
}

// T returns the translation for a key in the given language
func T(lang, key string) string {
	mu.RLock()
	defer mu.RUnlock()

	// Normalize language code
	lang = normalizeLang(lang)

	if trans, ok := translations[lang]; ok {
		if val, ok := trans[key]; ok {
			return val
		}
	}

	// Fallback to default language
	if trans, ok := translations[defaultLang]; ok {
		if val, ok := trans[key]; ok {
			return val
		}
	}

	// Return key if no translation found
	return key
}

// normalizeLang normalizes language codes
func normalizeLang(lang string) string {
	lang = strings.ToLower(lang)
	
	// Handle zh-CN, zh-TW, zh-Hans, zh-Hant, etc.
	if strings.HasPrefix(lang, "zh") {
		return "zh"
	}
	
	// Handle en-US, en-GB, etc.
	if strings.HasPrefix(lang, "en") {
		return "en"
	}
	
	// Default to English for unsupported languages
	if _, ok := translations[lang]; !ok {
		return "en"
	}
	
	return lang
}

// GetLangFromAcceptHeader parses Accept-Language header and returns the best match
func GetLangFromAcceptHeader(acceptLang string) string {
	if acceptLang == "" {
		return defaultLang
	}

	// Parse Accept-Language header
	// Format: en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7
	parts := strings.Split(acceptLang, ",")
	for _, part := range parts {
		lang := strings.TrimSpace(strings.Split(part, ";")[0])
		normalized := normalizeLang(lang)
		if _, ok := translations[normalized]; ok {
			return normalized
		}
	}

	return defaultLang
}

// SupportedLanguages returns list of supported languages
func SupportedLanguages() []string {
	mu.RLock()
	defer mu.RUnlock()

	langs := make([]string, 0, len(translations))
	for lang := range translations {
		langs = append(langs, lang)
	}
	return langs
}
