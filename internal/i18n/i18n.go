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
		"nav.home":           "Home",
		"nav.login":          "Login",
		"nav.register":       "Register",
		"nav.logout":         "Logout",
		"nav.profile":        "Profile",
		"nav.profile_center": "Profile Center",
		"nav.recharge":       "Recharge",
		"nav.vip":            "VIP",
		"nav.recharge_center": "Recharge Center",
		"nav.vip_member":     "VIP Member",
		"nav.language":       "Language",

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
		"register.username.placeholder": "2-32 characters, letters, numbers, underscore",
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
		"profile.title":                   "Profile",
		"profile.close":                   "Close",
		"profile.registered":              "Registered on",
		"profile.hero_title":              "Profile Center",
		"profile.hero_subtitle":           "Manage your account information and membership",
		"profile.vip_member":              "VIP Member",
		"profile.vip_member_subtitle":     "View your membership status and benefits",
		"profile.current_level":           "Current Level",
		"profile.vip_expire_calculating":  "Calculating VIP expiration...",
		"profile.vip_expire_at":           "Valid until",
		"profile.vip_permanent":           "Permanent",
		"profile.vip_expired":             "Expired",
		"profile.vip_renew_upgrade":       "Renew/Upgrade",
		"profile.not_vip":                 "Not a VIP member",
		"profile.activate_vip":            "Activate VIP",
		"profile.account_balance":         "Account Balance",
		"profile.account_balance_subtitle": "Manage your account funds",
		"profile.available_balance":       "Available Balance",
		"profile.recharge":                "Recharge",
		"profile.redeem_gift_card":        "Redeem Gift Card",
		"profile.account_info":            "Account Information",
		"profile.account_info_subtitle":   "Your basic account information",
		"profile.username":                "Username",
		"profile.email":                   "Email",
		"profile.display_name":            "Display Name",
		"profile.registration_time":       "Registration Time",
		"profile.account_status":          "Account Status",
		"profile.status_active":           "Active",
		"profile.status_disabled":         "Disabled",
		"profile.edit_profile":            "Edit Profile",
		"profile.change_password":         "Change Password",
		"profile.quick_actions":           "Quick Actions",
		"profile.quick_actions_subtitle":  "Common feature shortcuts",
		"profile.recharge_center":         "Recharge Center",
		"profile.vip_membership":          "VIP Membership",
		"profile.account_settings":        "Account Settings",
		"profile.logout":                  "Logout",
		"profile.vip_benefits":            "VIP Benefits",
		"profile.vip_benefits_subtitle":   "Exclusive member benefits",
		"profile.benefit_support":         "Priority Support",
		"profile.benefit_exclusive":       "Exclusive Features",
		"profile.benefit_more":            "More Benefits",
		"profile.view_all_benefits":       "View All Benefits",
		"profile.edit_profile_title":      "Edit Profile",
		"profile.display_name_label":      "Display Name",
		"profile.avatar_url":              "Avatar URL",
		"profile.cancel":                  "Cancel",
		"profile.save":                    "Save",
		"profile.gift_card_title":         "Redeem Gift Card",
		"profile.gift_card_hint":          "Enter gift card code to add balance to your account",
		"profile.gift_card_placeholder":   "XXXX-XXXX-XXXX-XXXX",
		"profile.gift_card_format_hint":   "Enter 16-digit gift card code (format: XXXX-XXXX-XXXX-XXXX)",
		"profile.redeem":                  "Redeem",
		"profile.change_password_title":   "Change Password",
		"profile.old_password":            "Old Password",
		"profile.old_password_placeholder": "Enter old password",
		"profile.new_password":            "New Password",
		"profile.new_password_placeholder": "Enter new password (at least 6 characters)",
		"profile.confirm_password":        "Confirm New Password",
		"profile.confirm_password_placeholder": "Enter new password again",
		"profile.confirm_change":          "Confirm Change",
		"profile.login_required":          "Please Log In",
		"profile.login_required_desc":     "You need to log in to access the profile center",
		"profile.login_now":               "Log In Now",

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
		"error.invalid_username":  "Username can only contain letters, numbers and underscores, 2-32 characters",
		"error.invalid_password":  "Password must be at least 6 characters",
		"error.email_exists":      "Email already registered",
		"error.username_exists":   "Username already taken",
		"error.user_not_found":    "User not found",
		"error.account_disabled":  "Account has been disabled",
		"error.invalid_token":     "Invalid token",
		"error.token_expired":     "Token has expired",

		// Gift Card VIP Warning
		"gift_card.vip_warning_title":          "VIP Conflict Warning",
		"gift_card.vip_warning_message":        "You currently have an active VIP membership. The VIP included in this gift card will NOT be applied because your current VIP is still valid.",
		"gift_card.vip_warning_current":        "Your current VIP",
		"gift_card.vip_warning_card_vip":       "Gift card VIP",
		"gift_card.vip_warning_expires":        "Expires",
		"gift_card.vip_warning_permanent":      "Permanent",
		"gift_card.vip_warning_days":           "days",
		"gift_card.vip_warning_confirm":        "Continue Redemption",
		"gift_card.vip_warning_cancel":         "Cancel",
		"gift_card.vip_warning_balance_note":   "Note: The balance portion of the gift card will still be credited to your account.",
		"gift_card.vip_skipped":                "Gift card redeemed successfully. VIP was not applied because you already have an active VIP membership.",
		"gift_card.preview_error":              "Unable to preview gift card",
		"gift_card.balance":                    "Balance",
		"gift_card.balance_added":              "Balance added:",
		"gift_card.vip_granted":                "VIP granted:",
		"gift_card.redeem_success":             "Redemption Successful",
		"gift_card.redeem_success_title":       "Gift card redeemed successfully!",
		"gift_card.current_balance":            "Current balance:",
		"gift_card.confirm_btn":                "OK",

		// Third-party Account Binding
		"binding.title":                     "Third-party Account Binding",
		"binding.subtitle":                  "Link your third-party accounts for easier login",
		"binding.google":                    "Google Account",
		"binding.steam":                     "Steam Account",
		"binding.discord":                   "Discord Account",
		"binding.bound":                     "Linked",
		"binding.not_bound":                 "Not Linked",
		"binding.bind":                      "Link",
		"binding.unbind":                    "Unlink",
		"binding.bind_disabled":             "Linking disabled",
		"binding.unbind_disabled":           "Unlinking disabled",
		"binding.unbind_confirm_title":      "Confirm Unlink",
		"binding.unbind_confirm_message":    "Are you sure you want to unlink this account?",
		"binding.unbind_confirm":            "Confirm",
		"binding.unbind_cancel":             "Cancel",
		"binding.unbind_success":            "Account unlinked successfully",
		"binding.unbind_error":              "Failed to unlink account",
		"binding.bind_success":              "Account linked successfully",
		"binding.bind_error":                "Failed to link account",
		"binding.already_bound":             "This account is already linked to another user",
		"binding.login_first":               "Please log in to this account first and unlink it",
		"binding.empty_state":               "No third-party login methods available",
	},
	"zh": {
		// Common
		"app.name":        "Common Login Service",
		"app.title":       "统一身份认证服务",
		"app.description": "安全、便捷的用户认证解决方案。支持多种登录方式，轻松集成到您的系统中。",

		// Navigation
		"nav.home":           "首页",
		"nav.login":          "登录",
		"nav.register":       "注册",
		"nav.logout":         "退出登录",
		"nav.profile":        "个人资料",
		"nav.profile_center": "个人中心",
		"nav.recharge":       "充值",
		"nav.vip":            "VIP",
		"nav.recharge_center": "充值中心",
		"nav.vip_member":     "VIP会员",
		"nav.language":       "语言",

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
		"profile.title":                   "个人资料",
		"profile.close":                   "关闭",
		"profile.registered":              "注册于",
		"profile.hero_title":              "个人中心",
		"profile.hero_subtitle":           "管理您的账户信息和会员权益",
		"profile.vip_member":              "VIP会员",
		"profile.vip_member_subtitle":     "查看您的会员权益和状态",
		"profile.current_level":           "当前会员等级",
		"profile.vip_expire_calculating":  "会员有效期计算中...",
		"profile.vip_expire_at":           "有效期至",
		"profile.vip_permanent":           "永久",
		"profile.vip_expired":             "已过期",
		"profile.vip_renew_upgrade":       "续费/升级",
		"profile.not_vip":                 "您还不是VIP会员",
		"profile.activate_vip":            "立即开通VIP",
		"profile.account_balance":         "账户余额",
		"profile.account_balance_subtitle": "管理您的账户资金",
		"profile.available_balance":       "可用余额",
		"profile.recharge":                "充值",
		"profile.redeem_gift_card":        "兑换礼品卡",
		"profile.account_info":            "账户信息",
		"profile.account_info_subtitle":   "您的基本账户信息",
		"profile.username":                "用户名",
		"profile.email":                   "邮箱",
		"profile.display_name":            "显示名称",
		"profile.registration_time":       "注册时间",
		"profile.account_status":          "账户状态",
		"profile.status_active":           "正常",
		"profile.status_disabled":         "已禁用",
		"profile.edit_profile":            "编辑个人资料",
		"profile.change_password":         "修改密码",
		"profile.quick_actions":           "快捷操作",
		"profile.quick_actions_subtitle":  "常用功能入口",
		"profile.recharge_center":         "充值中心",
		"profile.vip_membership":          "VIP会员",
		"profile.account_settings":        "账号设置",
		"profile.logout":                  "退出登录",
		"profile.vip_benefits":            "VIP特权",
		"profile.vip_benefits_subtitle":   "会员专属权益",
		"profile.benefit_support":         "优先支持",
		"profile.benefit_exclusive":       "专属功能",
		"profile.benefit_more":            "更多特权",
		"profile.view_all_benefits":       "查看全部VIP特权",
		"profile.edit_profile_title":      "编辑个人资料",
		"profile.display_name_label":      "显示名称",
		"profile.avatar_url":              "头像URL",
		"profile.cancel":                  "取消",
		"profile.save":                    "保存",
		"profile.gift_card_title":         "兑换礼品卡",
		"profile.gift_card_hint":          "输入礼品卡码，余额将自动添加到您的账户",
		"profile.gift_card_placeholder":   "XXXX-XXXX-XXXX-XXXX",
		"profile.gift_card_format_hint":   "请输入16位礼品卡码（格式：XXXX-XXXX-XXXX-XXXX）",
		"profile.redeem":                  "兑换",
		"profile.change_password_title":   "修改密码",
		"profile.old_password":            "原密码",
		"profile.old_password_placeholder": "请输入原密码",
		"profile.new_password":            "新密码",
		"profile.new_password_placeholder": "请输入新密码（至少6位）",
		"profile.confirm_password":        "确认新密码",
		"profile.confirm_password_placeholder": "请再次输入新密码",
		"profile.confirm_change":          "确认修改",
		"profile.login_required":          "请先登录",
		"profile.login_required_desc":     "您需要登录后才能访问个人中心",
		"profile.login_now":               "立即登录",

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
		"error.invalid_username":  "用户名只能包含字母、数字和下划线，长度2-32个字符",
		"error.invalid_password":  "密码长度至少6个字符",
		"error.email_exists":      "邮箱已被注册",
		"error.username_exists":   "用户名已被使用",
		"error.user_not_found":    "用户不存在",
		"error.account_disabled":  "账户已被禁用",
		"error.invalid_token":     "无效的令牌",
		"error.token_expired":     "重置令牌已过期",

		// Gift Card VIP Warning
		"gift_card.vip_warning_title":          "VIP冲突提醒",
		"gift_card.vip_warning_message":        "您当前已有有效的VIP会员。本礼品卡中的VIP将不会生效，因为您的当前VIP仍然有效。",
		"gift_card.vip_warning_current":        "您当前的VIP",
		"gift_card.vip_warning_card_vip":       "礼品卡VIP",
		"gift_card.vip_warning_expires":        "到期时间",
		"gift_card.vip_warning_permanent":      "永久",
		"gift_card.vip_warning_days":           "天",
		"gift_card.vip_warning_confirm":        "继续兑换",
		"gift_card.vip_warning_cancel":         "取消",
		"gift_card.vip_warning_balance_note":   "注意：礼品卡中的余额部分仍将充值到您的账户。",
		"gift_card.vip_skipped":                "礼品卡兑换成功。由于您已有有效的VIP会员，礼品卡中的VIP未生效。",
		"gift_card.preview_error":              "无法预览礼品卡",
		"gift_card.balance":                    "余额",
		"gift_card.balance_added":              "已添加余额：",
		"gift_card.vip_granted":                "已获得VIP：",
		"gift_card.redeem_success":             "兑换成功",
		"gift_card.redeem_success_title":       "礼品卡兑换成功！",
		"gift_card.current_balance":            "当前余额：",
		"gift_card.confirm_btn":                "确定",

		// Third-party Account Binding
		"binding.title":                     "第三方账号绑定",
		"binding.subtitle":                  "关联第三方账号，方便快捷登录",
		"binding.google":                    "Google账号",
		"binding.steam":                     "Steam账号",
		"binding.discord":                   "Discord账号",
		"binding.bound":                     "已绑定",
		"binding.not_bound":                 "未绑定",
		"binding.bind":                      "绑定",
		"binding.unbind":                    "解绑",
		"binding.bind_disabled":             "绑定功能已关闭",
		"binding.unbind_disabled":           "解绑功能已关闭",
		"binding.unbind_confirm_title":      "确认解绑",
		"binding.unbind_confirm_message":    "确定要解绑该账号吗？",
		"binding.unbind_confirm":            "确认",
		"binding.unbind_cancel":             "取消",
		"binding.unbind_success":            "账号解绑成功",
		"binding.unbind_error":              "账号解绑失败",
		"binding.bind_success":              "账号绑定成功",
		"binding.bind_error":                "账号绑定失败",
		"binding.already_bound":             "该账号已被其他用户绑定",
		"binding.login_first":               "如需绑定请先登录该账号解绑",
		"binding.empty_state":               "暂无可用的第三方登录方式",
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
