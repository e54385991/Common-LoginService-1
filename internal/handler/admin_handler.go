package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/repository"
	"github.com/e54385991/Common-LoginService/pkg/utils"
	"github.com/gin-gonic/gin"
)

// Dark mode constants
const (
	DarkModeSystem = "system" // Follow system preference
	DarkModeDark   = "dark"   // Always dark mode
	DarkModeLight  = "light"  // Always light mode
)

// AdminHandler handles admin requests
type AdminHandler struct {
	cfg            *config.Config
	configRepo     *repository.ConfigRepository
	userRepo       *repository.UserRepository
	apiTokenRepo   *repository.APITokenRepository
	giftCardRepo   *repository.GiftCardRepository
	balanceLogRepo *repository.BalanceLogRepository
	sessionStore   repository.SessionStore
	loginLogRepo   *repository.LoginLogRepository
}

// AdminLoginRequest represents admin login request
type AdminLoginRequest struct {
	Username string `json:"username" binding:"required" example:"admin"`
	Password string `json:"password" binding:"required" example:"admin123"`
}

// UpdateUserBalanceRequest represents user balance update request
type UpdateUserBalanceRequest struct {
	Amount float64 `json:"amount" example:"100.50"`
}

// SetUserBalanceRequest represents user balance set request
type SetUserBalanceRequest struct {
	Balance float64 `json:"balance" example:"500.00"`
}

// SetUserVIPLevelRequest represents user VIP level set request
type SetUserVIPLevelRequest struct {
	VIPLevel int `json:"vip_level" example:"3"`
}

// RenewUserVIPRequest represents user VIP renewal request
type RenewUserVIPRequest struct {
	VIPLevel     int `json:"vip_level" example:"3"`      // VIP level to set (0 means keep current level)
	DurationDays int `json:"duration_days" example:"30"` // Duration to add in days (0 means permanent)
}

// SetUserStatusRequest represents user status set request
type SetUserStatusRequest struct {
	IsActive bool `json:"is_active" example:"true"`
}

// GoogleOAuthSettings represents Google OAuth settings
type GoogleOAuthSettings struct {
	Enabled      bool   `json:"enabled" example:"true"`
	ClientID     string `json:"client_id" example:"your-client-id"`
	ClientSecret string `json:"client_secret" example:"****"`
	RedirectURL  string `json:"redirect_url" example:"http://localhost:8080/api/auth/google/callback"`
}

// SteamOAuthSettings represents Steam OAuth settings
type SteamOAuthSettings struct {
	Enabled     bool   `json:"enabled" example:"true"`
	APIKey      string `json:"api_key" example:"****"`
	RedirectURL string `json:"redirect_url" example:"http://localhost:8080/api/auth/steam/callback"`
}

// DiscordOAuthSettings represents Discord OAuth settings
type DiscordOAuthSettings struct {
	Enabled      bool   `json:"enabled" example:"true"`
	ClientID     string `json:"client_id" example:"your-client-id"`
	ClientSecret string `json:"client_secret" example:"****"`
	RedirectURL  string `json:"redirect_url" example:"http://localhost:8080/api/auth/discord/callback"`
}

// GmailAPISettings represents Gmail API settings
type GmailAPISettings struct {
	Enabled      bool   `json:"enabled" example:"true"`
	SenderEmail  string `json:"sender_email" example:"noreply@example.com"`
	ClientID     string `json:"client_id" example:"your-client-id"`
	ClientSecret string `json:"client_secret" example:"****"`
	RefreshToken string `json:"refresh_token" example:"****"`
}

// JWTSettings represents JWT settings
type JWTSettings struct {
	ExpireHour int `json:"expire_hour" example:"24"`
}

// CaptchaSettings represents captcha settings
type CaptchaSettings struct {
	Enabled bool `json:"enabled" example:"true"`
}

// AdminSettingsResponse represents admin settings response
type AdminSettingsResponse struct {
	GoogleOAuth  GoogleOAuthSettings  `json:"google_oauth"`
	SteamOAuth   SteamOAuthSettings   `json:"steam_oauth"`
	DiscordOAuth DiscordOAuthSettings `json:"discord_oauth"`
	GmailAPI     GmailAPISettings     `json:"gmail_api"`
	JWT          JWTSettings          `json:"jwt"`
	Captcha      CaptchaSettings      `json:"captcha"`
}

// UpdateGoogleOAuthRequest represents Google OAuth update request
type UpdateGoogleOAuthRequest struct {
	Enabled      bool   `json:"enabled" example:"true"`
	ClientID     string `json:"client_id" example:"your-client-id"`
	ClientSecret string `json:"client_secret" example:"your-client-secret"`
	RedirectURL  string `json:"redirect_url" example:"http://localhost:8080/api/auth/google/callback"`
}

// UpdateSteamOAuthRequest represents Steam OAuth update request
type UpdateSteamOAuthRequest struct {
	Enabled     bool   `json:"enabled" example:"true"`
	APIKey      string `json:"api_key" example:"your-steam-api-key"`
	RedirectURL string `json:"redirect_url" example:"http://localhost:8080/api/auth/steam/callback"`
}

// UpdateDiscordOAuthRequest represents Discord OAuth update request
type UpdateDiscordOAuthRequest struct {
	Enabled      bool   `json:"enabled" example:"true"`
	ClientID     string `json:"client_id" example:"your-client-id"`
	ClientSecret string `json:"client_secret" example:"your-client-secret"`
	RedirectURL  string `json:"redirect_url" example:"http://localhost:8080/api/auth/discord/callback"`
}

// UpdateGmailAPIRequest represents Gmail API update request
type UpdateGmailAPIRequest struct {
	Enabled      bool   `json:"enabled" example:"true"`
	SenderEmail  string `json:"sender_email" example:"noreply@example.com"`
	ClientID     string `json:"client_id" example:"your-client-id"`
	ClientSecret string `json:"client_secret" example:"your-client-secret"`
	RefreshToken string `json:"refresh_token" example:"your-refresh-token"`
}

// UpdateJWTRequest represents JWT update request
type UpdateJWTRequest struct {
	ExpireHour int    `json:"expire_hour" example:"24"`
	Secret     string `json:"secret" example:"your-jwt-secret"`
}

// UpdateCaptchaRequest represents captcha update request
type UpdateCaptchaRequest struct {
	Enabled bool `json:"enabled" example:"true"`
}

// NewAdminHandler creates a new AdminHandler
func NewAdminHandler(cfg *config.Config, configRepo *repository.ConfigRepository, userRepo *repository.UserRepository, apiTokenRepo *repository.APITokenRepository, giftCardRepo *repository.GiftCardRepository, balanceLogRepo *repository.BalanceLogRepository, sessionStore repository.SessionStore) *AdminHandler {
	return &AdminHandler{
		cfg:            cfg,
		configRepo:     configRepo,
		userRepo:       userRepo,
		apiTokenRepo:   apiTokenRepo,
		giftCardRepo:   giftCardRepo,
		balanceLogRepo: balanceLogRepo,
		sessionStore:   sessionStore,
	}
}

// SetLoginLogRepo sets the login log repository for AdminHandler
func (h *AdminHandler) SetLoginLogRepo(loginLogRepo *repository.LoginLogRepository) {
	h.loginLogRepo = loginLogRepo
}

// AdminLoginPage renders the admin login page
func (h *AdminHandler) AdminLoginPage(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_login.html", gin.H{
		"lang": lang,
	})
}

// AdminLogin handles admin login
// @Summary Admin login
// @Description Authenticate admin user
// @Tags admin
// @Accept json
// @Produce json
// @Param request body AdminLoginRequest true "Admin login request"
// @Success 200 {object} Response "Login successful"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Invalid credentials"
// @Router /admin/login [post]
func (h *AdminHandler) AdminLogin(c *gin.Context) {
	var input struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Invalid request",
		})
		return
	}

	if input.Username != h.cfg.Admin.Username || input.Password != h.cfg.Admin.Password {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "Invalid credentials",
		})
		return
	}

	// Set admin session cookie (secure flag based on request protocol)
	// Path set to "/" to work for both /admin pages and /api/admin API endpoints
	c.SetCookie("admin_session", "true", 3600*24, "/", "", isSecureRequest(c), true)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Login successful",
	})
}

// AdminLogout handles admin logout
func (h *AdminHandler) AdminLogout(c *gin.Context) {
	c.SetCookie("admin_session", "", -1, "/", "", isSecureRequest(c), true)
	c.Redirect(http.StatusFound, "/admin/login")
}

// AdminDashboard renders the admin dashboard
func (h *AdminHandler) AdminDashboard(c *gin.Context) {
	lang := c.GetString("lang")
	// Get user count
	users, total, _ := h.userRepo.List(1, 1)
	_ = users

	c.HTML(http.StatusOK, "admin_dashboard.html", gin.H{
		"lang":        lang,
		"userCount":   total,
		"activeMenu":  "dashboard",
		"goVersion":   runtime.Version(),
		"ginVersion":  gin.Version,
		"dbType":      "MySQL",
	})
}

// AdminSettings renders the admin settings page
func (h *AdminHandler) AdminSettings(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_settings.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"activeMenu": "settings",
	})
}

// AdminUsers renders the admin users page
func (h *AdminHandler) AdminUsers(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_users.html", gin.H{
		"lang":       lang,
		"activeMenu": "users",
	})
}

// AdminIntegrationGuide renders the integration guide page for external systems
func (h *AdminHandler) AdminIntegrationGuide(c *gin.Context) {
	lang := c.GetString("lang")
	
	// Get base URL from config or request
	baseURL := utils.GetBaseURL(c, h.cfg.Site.BaseURL)
	
	c.HTML(http.StatusOK, "admin_integration_guide.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"baseURL":    baseURL,
		"activeMenu": "integration-guide",
	})
}

// GetSettings returns the current settings
// @Summary Get admin settings
// @Description Get current system settings
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} Response{data=AdminSettingsResponse} "Settings retrieved"
// @Failure 401 {object} Response "Unauthorized"
// @Router /admin/settings [get]
func (h *AdminHandler) GetSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"google_oauth": gin.H{
				"enabled":       h.cfg.GoogleOAuth.Enabled,
				"client_id":     h.cfg.GoogleOAuth.ClientID,
				"client_secret": maskSecret(h.cfg.GoogleOAuth.ClientSecret),
				"redirect_url":  h.cfg.GoogleOAuth.RedirectURL,
				"allow_bind":    h.cfg.GoogleOAuth.AllowBind,
				"allow_unbind":  h.cfg.GoogleOAuth.AllowUnbind,
			},
			"steam_oauth": gin.H{
				"enabled":      h.cfg.SteamOAuth.Enabled,
				"api_key":      maskSecret(h.cfg.SteamOAuth.APIKey),
				"redirect_url": h.cfg.SteamOAuth.RedirectURL,
				"allow_bind":   h.cfg.SteamOAuth.AllowBind,
				"allow_unbind": h.cfg.SteamOAuth.AllowUnbind,
			},
			"discord_oauth": gin.H{
				"enabled":       h.cfg.DiscordOAuth.Enabled,
				"client_id":     h.cfg.DiscordOAuth.ClientID,
				"client_secret": maskSecret(h.cfg.DiscordOAuth.ClientSecret),
				"redirect_url":  h.cfg.DiscordOAuth.RedirectURL,
				"allow_bind":    h.cfg.DiscordOAuth.AllowBind,
				"allow_unbind":  h.cfg.DiscordOAuth.AllowUnbind,
			},
			"gmail_api": gin.H{
				"enabled":       h.cfg.GmailAPI.Enabled,
				"sender_email":  h.cfg.GmailAPI.SenderEmail,
				"client_id":     h.cfg.GmailAPI.ClientID,
				"client_secret": maskSecret(h.cfg.GmailAPI.ClientSecret),
				"refresh_token": maskSecret(h.cfg.GmailAPI.RefreshToken),
			},
			"jwt": gin.H{
				"expire_hour": h.cfg.JWT.ExpireHour,
			},
			"captcha": gin.H{
				"enabled": h.cfg.Captcha.Enabled,
			},
		},
	})
}

// UpdateGoogleOAuth updates Google OAuth settings
// @Summary Update Google OAuth settings
// @Description Update Google OAuth configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateGoogleOAuthRequest true "Google OAuth settings"
// @Success 200 {object} Response "Settings updated"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 500 {object} Response "Failed to save settings"
// @Router /admin/settings/google-oauth [put]
func (h *AdminHandler) UpdateGoogleOAuth(c *gin.Context) {
	var input struct {
		Enabled      bool   `json:"enabled"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURL  string `json:"redirect_url"`
		AllowBind    bool   `json:"allow_bind"`
		AllowUnbind  bool   `json:"allow_unbind"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.GoogleOAuth.Enabled = input.Enabled
	h.cfg.GoogleOAuth.ClientID = input.ClientID
	if input.ClientSecret != "" && !isMasked(input.ClientSecret) {
		h.cfg.GoogleOAuth.ClientSecret = input.ClientSecret
	}
	h.cfg.GoogleOAuth.RedirectURL = input.RedirectURL
	h.cfg.GoogleOAuth.AllowBind = input.AllowBind
	h.cfg.GoogleOAuth.AllowUnbind = input.AllowUnbind

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Google OAuth 设置已更新",
	})
}

// UpdateSteamOAuth updates Steam OAuth settings
// @Summary Update Steam OAuth settings
// @Description Update Steam OAuth configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateSteamOAuthRequest true "Steam OAuth settings"
// @Success 200 {object} Response "Settings updated"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 500 {object} Response "Failed to save settings"
// @Router /admin/settings/steam-oauth [put]
func (h *AdminHandler) UpdateSteamOAuth(c *gin.Context) {
	var input struct {
		Enabled     bool   `json:"enabled"`
		APIKey      string `json:"api_key"`
		RedirectURL string `json:"redirect_url"`
		AllowBind   bool   `json:"allow_bind"`
		AllowUnbind bool   `json:"allow_unbind"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.SteamOAuth.Enabled = input.Enabled
	if input.APIKey != "" && !isMasked(input.APIKey) {
		h.cfg.SteamOAuth.APIKey = input.APIKey
	}
	h.cfg.SteamOAuth.RedirectURL = input.RedirectURL
	h.cfg.SteamOAuth.AllowBind = input.AllowBind
	h.cfg.SteamOAuth.AllowUnbind = input.AllowUnbind

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Steam OAuth 设置已更新",
	})
}

// UpdateDiscordOAuth updates Discord OAuth settings
// @Summary Update Discord OAuth settings
// @Description Update Discord OAuth configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateDiscordOAuthRequest true "Discord OAuth settings"
// @Success 200 {object} Response "Settings updated"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 500 {object} Response "Failed to save settings"
// @Router /admin/settings/discord-oauth [put]
func (h *AdminHandler) UpdateDiscordOAuth(c *gin.Context) {
	var input struct {
		Enabled      bool   `json:"enabled"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURL  string `json:"redirect_url"`
		AllowBind    bool   `json:"allow_bind"`
		AllowUnbind  bool   `json:"allow_unbind"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.DiscordOAuth.Enabled = input.Enabled
	h.cfg.DiscordOAuth.ClientID = input.ClientID
	if input.ClientSecret != "" && !isMasked(input.ClientSecret) {
		h.cfg.DiscordOAuth.ClientSecret = input.ClientSecret
	}
	h.cfg.DiscordOAuth.RedirectURL = input.RedirectURL
	h.cfg.DiscordOAuth.AllowBind = input.AllowBind
	h.cfg.DiscordOAuth.AllowUnbind = input.AllowUnbind

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Discord OAuth 设置已更新",
	})
}

// UpdateGmailAPI updates Gmail API settings
// @Summary Update Gmail API settings
// @Description Update Gmail API configuration for sending emails
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateGmailAPIRequest true "Gmail API settings"
// @Success 200 {object} Response "Settings updated"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 500 {object} Response "Failed to save settings"
// @Router /admin/settings/gmail-api [put]
func (h *AdminHandler) UpdateGmailAPI(c *gin.Context) {
	var input struct {
		Enabled      bool   `json:"enabled"`
		SenderEmail  string `json:"sender_email"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.GmailAPI.Enabled = input.Enabled
	h.cfg.GmailAPI.SenderEmail = input.SenderEmail
	
	// Update OAuth2 credentials if provided
	if input.ClientID != "" {
		h.cfg.GmailAPI.ClientID = input.ClientID
	}
	if input.ClientSecret != "" && !isMasked(input.ClientSecret) {
		h.cfg.GmailAPI.ClientSecret = input.ClientSecret
	}
	if input.RefreshToken != "" && !isMasked(input.RefreshToken) {
		h.cfg.GmailAPI.RefreshToken = input.RefreshToken
	}

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Gmail API 设置已更新",
	})
}

// UpdateJWT updates JWT settings
// @Summary Update JWT settings
// @Description Update JWT configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateJWTRequest true "JWT settings"
// @Success 200 {object} Response "Settings updated"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 500 {object} Response "Failed to save settings"
// @Router /admin/settings/jwt [put]
func (h *AdminHandler) UpdateJWT(c *gin.Context) {
	var input struct {
		ExpireHour int    `json:"expire_hour"`
		Secret     string `json:"secret"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if input.ExpireHour > 0 {
		h.cfg.JWT.ExpireHour = input.ExpireHour
	}
	if input.Secret != "" && !isMasked(input.Secret) {
		h.cfg.JWT.Secret = input.Secret
	}

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "JWT 设置已更新",
	})
}

// UpdateCaptcha updates captcha settings
// @Summary Update captcha settings
// @Description Update captcha configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateCaptchaRequest true "Captcha settings"
// @Success 200 {object} Response "Settings updated"
// @Failure 400 {object} Response "Bad request"
// @Failure 401 {object} Response "Unauthorized"
// @Failure 500 {object} Response "Failed to save settings"
// @Router /admin/settings/captcha [put]
func (h *AdminHandler) UpdateCaptcha(c *gin.Context) {
	var input struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.Captcha.Enabled = input.Enabled

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "验证码设置已更新",
	})
}

// AccessSettings represents access control settings
type AccessSettings struct {
	RegistrationEnabled  bool   `json:"registration_enabled" example:"true"`
	LoginEnabled         bool   `json:"login_enabled" example:"true"`
	RegistrationMessage  string `json:"registration_message" example:"注册功能暂时关闭"`
	LoginMessage         string `json:"login_message" example:"登录功能暂时关闭"`
	RegistrationStartUID uint   `json:"registration_start_uid" example:"26000"` // Minimum UID for backend registration (0 = no restriction)
	AllowEmailLogin      bool   `json:"allow_email_login" example:"true"`       // Allow login with email
	AllowUsernameLogin   bool   `json:"allow_username_login" example:"false"`   // Allow login with username
}

// GetAccessSettings returns access control settings
// @Summary Get access settings
// @Description Get current registration and login access settings
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response{data=AccessSettings} "Access settings retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/access [get]
func (h *AdminHandler) GetAccessSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"registration_enabled":         h.cfg.Access.RegistrationEnabled,
			"login_enabled":                h.cfg.Access.LoginEnabled,
			"registration_message":         h.cfg.Access.RegistrationMessage,
			"login_message":                h.cfg.Access.LoginMessage,
			"registration_start_uid":       h.cfg.Access.RegistrationStartUID,
			"allow_email_login":            h.cfg.Access.AllowEmailLogin,
			"allow_username_login":         h.cfg.Access.AllowUsernameLogin,
			"require_email_verification":   h.cfg.Access.RequireEmailVerification,
			"password_min_length":          h.cfg.Access.PasswordMinLength,
			"password_require_letter":      h.cfg.Access.PasswordRequireLetter,
			"password_require_number":      h.cfg.Access.PasswordRequireNumber,
			"password_require_special":     h.cfg.Access.PasswordRequireSpecial,
		},
	})
}

// UpdateAccessSettings updates access control settings
// @Summary Update access settings
// @Description Update registration and login access settings
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AccessSettings true "Access settings"
// @Success 200 {object} handler.Response "Settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/access [put]
func (h *AdminHandler) UpdateAccessSettings(c *gin.Context) {
	var input struct {
		RegistrationEnabled        bool   `json:"registration_enabled"`
		LoginEnabled               bool   `json:"login_enabled"`
		RegistrationMessage        string `json:"registration_message"`
		LoginMessage               string `json:"login_message"`
		RegistrationStartUID       uint   `json:"registration_start_uid"`
		AllowEmailLogin            bool   `json:"allow_email_login"`
		AllowUsernameLogin         bool   `json:"allow_username_login"`
		RequireEmailVerification   bool   `json:"require_email_verification"`
		PasswordMinLength          *int   `json:"password_min_length"`
		PasswordRequireLetter      *bool  `json:"password_require_letter"`
		PasswordRequireNumber      *bool  `json:"password_require_number"`
		PasswordRequireSpecial     *bool  `json:"password_require_special"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate: at least one login method must be enabled when login is enabled
	if input.LoginEnabled && !input.AllowEmailLogin && !input.AllowUsernameLogin {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "启用登录时，至少需要开启一种登录方式（邮箱或用户名）",
		})
		return
	}

	h.cfg.Access.RegistrationEnabled = input.RegistrationEnabled
	h.cfg.Access.LoginEnabled = input.LoginEnabled
	h.cfg.Access.RegistrationMessage = input.RegistrationMessage
	h.cfg.Access.LoginMessage = input.LoginMessage
	h.cfg.Access.RegistrationStartUID = input.RegistrationStartUID
	h.cfg.Access.AllowEmailLogin = input.AllowEmailLogin
	h.cfg.Access.AllowUsernameLogin = input.AllowUsernameLogin
	h.cfg.Access.RequireEmailVerification = input.RequireEmailVerification
	
	// Update password complexity settings if provided
	if input.PasswordMinLength != nil {
		minLen := *input.PasswordMinLength
		if minLen < 1 {
			minLen = 6
		}
		if minLen > 128 {
			minLen = 128
		}
		h.cfg.Access.PasswordMinLength = minLen
	}
	if input.PasswordRequireLetter != nil {
		h.cfg.Access.PasswordRequireLetter = *input.PasswordRequireLetter
	}
	if input.PasswordRequireNumber != nil {
		h.cfg.Access.PasswordRequireNumber = *input.PasswordRequireNumber
	}
	if input.PasswordRequireSpecial != nil {
		h.cfg.Access.PasswordRequireSpecial = *input.PasswordRequireSpecial
	}

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "访问控制设置已更新",
	})
}

// Helper functions
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "********"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

func isMasked(s string) bool {
	// Check if string contains consecutive asterisks (indicating it's masked)
	return strings.Contains(s, "****")
}

// hasPermission checks if the permissions string contains the required permission
// Permissions are stored as comma-separated values, e.g. "balance,vip,all"
func hasPermission(permissions, required string) bool {
	permList := strings.Split(permissions, ",")
	for _, p := range permList {
		if strings.TrimSpace(p) == required || strings.TrimSpace(p) == "all" {
			return true
		}
	}
	return false
}

// GetUser returns a specific user by ID
// @Summary Get user by ID
// @Description Get a specific user's information by their ID
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} handler.Response "User retrieved"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Router /admin/users/{id} [get]
func (h *AdminHandler) GetUser(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	user, err := h.userRepo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    user,
	})
}

// ListUsers lists users with pagination and optional search
// @Summary List users
// @Description Get users with pagination and optional search by username, email, or display name
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param keyword query string false "Search keyword (username, email, display name)"
// @Success 200 {object} handler.Response "Users retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/users [get]
func (h *AdminHandler) ListUsers(c *gin.Context) {
	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	keyword := c.Query("keyword")

	var users []model.User
	var total int64
	var err error

	if keyword != "" {
		users, total, err = h.userRepo.Search(keyword, page, pageSize)
	} else {
		users, total, err = h.userRepo.List(page, pageSize)
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取用户列表失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"users":     users,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// AdminBalanceLogs renders the admin balance logs page
func (h *AdminHandler) AdminBalanceLogs(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_balance_logs.html", gin.H{
		"lang":       lang,
		"activeMenu": "balance-logs",
	})
}

// ListBalanceLogs lists balance logs with pagination and optional filters
// @Summary List balance logs
// @Description Get balance logs with pagination and optional filters
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param user_id query int false "Filter by user ID"
// @Param type query string false "Filter by type (admin, api, gift_card, purchase_vip, payment)"
// @Success 200 {object} handler.Response "Balance logs retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/balance-logs [get]
func (h *AdminHandler) ListBalanceLogs(c *gin.Context) {
	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	var userID *uint
	if uid := c.Query("user_id"); uid != "" {
		var id uint
		if _, err := parseUint(uid, &id); err == nil {
			userID = &id
		}
	}

	logType := c.Query("type")

	logs, total, err := h.balanceLogRepo.List(page, pageSize, userID, logType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取余额日志失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"logs":      logs,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}

// UpdateUserBalance updates a user's balance by adding/subtracting an amount
// @Summary Update user balance
// @Description Add or subtract from user's balance
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body UpdateUserBalanceRequest true "Balance update request"
// @Success 200 {object} handler.Response "Balance updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Router /admin/users/{id}/balance [post]
func (h *AdminHandler) UpdateUserBalance(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	var input struct {
		Amount float64 `json:"amount" binding:"required"`
		Reason string  `json:"reason"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Get user's balance before update
	userBefore, err := h.userRepo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}
	balanceBefore := userBefore.Balance

	user, err := h.userRepo.UpdateBalance(id, input.Amount)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	// Create balance log
	reason := input.Reason
	if reason == "" {
		if input.Amount > 0 {
			reason = "管理员增加余额"
		} else {
			reason = "管理员扣除余额"
		}
	}
	balanceLog := &model.BalanceLog{
		UserID:        id,
		Amount:        input.Amount,
		BalanceBefore: balanceBefore,
		BalanceAfter:  user.Balance,
		Type:          "admin",
		Reason:        reason,
		OperatorType:  "admin",
	}
	h.balanceLogRepo.Create(balanceLog)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "余额更新成功",
		"data":    user,
	})
}

// SetUserBalance sets a user's balance to a specific value
// @Summary Set user balance
// @Description Set user's balance to a specific value
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body SetUserBalanceRequest true "Balance set request"
// @Success 200 {object} handler.Response "Balance set"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Router /admin/users/{id}/balance [put]
func (h *AdminHandler) SetUserBalance(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	var input struct {
		Balance float64 `json:"balance"`
		Reason  string  `json:"reason"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if input.Balance < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "余额不能为负数",
		})
		return
	}

	// Get user's balance before update
	userBefore, err := h.userRepo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}
	balanceBefore := userBefore.Balance

	user, err := h.userRepo.SetBalance(id, input.Balance)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	// Create balance log
	reason := input.Reason
	if reason == "" {
		reason = "管理员设置余额"
	}
	balanceLog := &model.BalanceLog{
		UserID:        id,
		Amount:        input.Balance - balanceBefore,
		BalanceBefore: balanceBefore,
		BalanceAfter:  user.Balance,
		Type:          "admin",
		Reason:        reason,
		OperatorType:  "admin",
	}
	h.balanceLogRepo.Create(balanceLog)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "余额设置成功",
		"data":    user,
	})
}

// SetUserVIPLevel sets a user's VIP level
// @Summary Set user VIP level
// @Description Set user's VIP level
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body SetUserVIPLevelRequest true "VIP level set request"
// @Success 200 {object} handler.Response "VIP level set"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Router /admin/users/{id}/vip-level [put]
func (h *AdminHandler) SetUserVIPLevel(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	var input struct {
		VIPLevel int `json:"vip_level"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if input.VIPLevel < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "VIP等级不能为负数",
		})
		return
	}

	user, err := h.userRepo.SetVIPLevel(id, input.VIPLevel)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "VIP等级设置成功",
		"data":    user,
	})
}

// SetUserVIPExpireAtRequest represents user VIP expire at set request
type SetUserVIPExpireAtRequest struct {
	VIPExpireAt string `json:"vip_expire_at" example:"2025-12-31T23:59:59Z"` // ISO 8601 format, empty means clear
}

// SetUserVIPExpireAt sets a user's VIP expiration time
// @Summary Set user VIP expiration time
// @Description Set user's VIP expiration time. Use empty string to clear expiration (permanent VIP).
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body SetUserVIPExpireAtRequest true "VIP expiration set request"
// @Success 200 {object} handler.Response "VIP expiration set"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Router /admin/users/{id}/vip-expire [put]
func (h *AdminHandler) SetUserVIPExpireAt(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	var input struct {
		VIPExpireAt string `json:"vip_expire_at"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	var expireAt *time.Time
	if input.VIPExpireAt != "" {
		t, err := time.Parse(time.RFC3339, input.VIPExpireAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "VIP到期时间格式错误，请使用ISO 8601格式，例如：2025-12-31T23:59:59Z",
			})
			return
		}
		expireAt = &t
	}

	user, err := h.userRepo.SetVIPExpireAt(id, expireAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "VIP到期时间设置成功",
		"data":    user,
	})
}

// RenewUserVIP renews/extends a user's VIP membership
// @Summary Renew user VIP
// @Description Renew/extend a user's VIP membership. If the user has active VIP, the duration is added to the current expiration. Otherwise, it starts from now.
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body RenewUserVIPRequest true "VIP renewal request"
// @Success 200 {object} handler.Response "VIP renewed"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Router /admin/users/{id}/vip-renew [post]
func (h *AdminHandler) RenewUserVIP(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	var input struct {
		VIPLevel     int `json:"vip_level"`
		DurationDays int `json:"duration_days"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if input.VIPLevel < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "VIP等级不能为负数",
		})
		return
	}

	if input.DurationDays < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "续期天数不能为负数",
		})
		return
	}

	user, err := h.userRepo.RenewVIPLevel(id, input.VIPLevel, input.DurationDays)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "VIP续期成功",
		"data":    user,
	})
}

// SetUserStatus sets a user's active status
// @Summary Set user status
// @Description Enable or disable a user account
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Param request body SetUserStatusRequest true "Status set request"
// @Success 200 {object} handler.Response "Status set"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Router /admin/users/{id}/status [put]
func (h *AdminHandler) SetUserStatus(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	var input struct {
		IsActive bool `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	user, err := h.userRepo.SetUserStatus(id, input.IsActive)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户状态设置成功",
		"data":    user,
	})
}

// ResetUserPassword resets a user's password to a random password
// @Summary Reset user password
// @Description Reset user's password to a new random password
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} handler.Response "Password reset successful"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Failure 500 {object} handler.Response "Failed to reset password"
// @Router /admin/users/{id}/reset-password [post]
func (h *AdminHandler) ResetUserPassword(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	// Generate a random password (12 characters)
	// 9 bytes produces 12 base64 URL-safe characters (ceil(9*8/6) = 12)
	randomBytes := make([]byte, 9)
	if _, err := rand.Read(randomBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "生成随机密码失败",
		})
		return
	}
	newPassword := base64.URLEncoding.EncodeToString(randomBytes)

	// Hash the new password
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "密码加密失败",
		})
		return
	}

	// Reset the user's password
	user, err := h.userRepo.ResetPassword(id, hashedPassword)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或重置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":      true,
		"message":      "密码重置成功",
		"new_password": newPassword,
		"data":         user,
	})
}

// LogoutUser forces logout of a specific user by deleting all their sessions
// @Summary Force logout user
// @Description Force logout a user by deleting all their active sessions
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "User ID"
// @Success 200 {object} handler.Response "User logged out"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 404 {object} handler.Response "User not found"
// @Failure 500 {object} handler.Response "Failed to logout user"
// @Router /admin/users/{id}/logout [post]
func (h *AdminHandler) LogoutUser(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	// Verify user exists
	_, err := h.userRepo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	// Delete all sessions for the user
	if err := h.sessionStore.DeleteByUserID(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "注销用户登录失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "已注销用户所有登录会话",
	})
}

// Helper function to parse uint from string
func parseUint(s string, result *uint) (bool, error) {
	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return false, err
	}
	*result = uint(val)
	return true, nil
}

// UpdateSiteSettingsRequest represents site settings update request
type UpdateSiteSettingsRequest struct {
	Title                 string `json:"title" example:"Common Login Service"`
	Description           string `json:"description" example:"统一身份认证服务"`
	Logo                  string `json:"logo" example:"https://example.com/logo.png"`
	DarkMode              string `json:"dark_mode" example:"system"`               // Dark mode setting: "system", "dark", "light"
	RedirectHomeToProfile bool   `json:"redirect_home_to_profile" example:"false"` // When enabled, redirect logged-in users from homepage to /profile
	BaseURL               string `json:"base_url" example:"https://user.yuelk.com"` // Forced site base URL (overrides auto-detected URL)
}

// UpdatePaymentSettingsRequest represents payment settings update request
type UpdatePaymentSettingsRequest struct {
	Enabled    bool   `json:"enabled" example:"true"`
	DemoMode   bool   `json:"demo_mode" example:"false"`
	ApiURL     string `json:"api_url" example:"https://pypay.meilanyv.cn/api/"`
	MerchantID string `json:"merchant_id" example:"your-merchant-id"`
	ApiKey     string `json:"api_key" example:"your-api-key"`
	NotifyURL  string `json:"notify_url" example:"https://your-domain.com/api/payment/notify"`
	ReturnURL  string `json:"return_url" example:"https://your-domain.com/payment/result"`
}

// VIPLevelRequest represents a single VIP level configuration
type VIPLevelRequest struct {
	Level       int     `json:"level" example:"1"`
	Name        string  `json:"name" example:"VIP 1"`
	Description string  `json:"description" example:"基础会员特权"`
	Price       float64 `json:"price" example:"9.9"`
	Duration    int     `json:"duration" example:"30"`
	Icon        string  `json:"icon" example:"bi-star"`
	Color       string  `json:"color" example:"#cd7f32"`
}

// UpdateVIPLevelsRequest represents VIP levels update request
type UpdateVIPLevelsRequest struct {
	VIPLevels []VIPLevelRequest `json:"vip_levels"`
}

// AdminVIPSettings renders the admin VIP settings page
func (h *AdminHandler) AdminVIPSettings(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_vip.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"activeMenu": "vip",
	})
}

// AdminProfileNavigation renders the admin profile navigation settings page
func (h *AdminHandler) AdminProfileNavigation(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_profile_navigation.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"activeMenu": "profile-navigation",
	})
}

// AdminMobileToolbar renders the admin mobile toolbar settings page
func (h *AdminHandler) AdminMobileToolbar(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_mobile_toolbar.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"activeMenu": "mobile-toolbar",
	})
}

// GetSiteSettings returns site settings
// @Summary Get site settings
// @Description Get current site configuration
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Site settings retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/site [get]
func (h *AdminHandler) GetSiteSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"title":       h.cfg.Site.Title,
			"title_i18n":  h.cfg.Site.TitleI18n,
			"description": h.cfg.Site.Description,
			"logo":        h.cfg.Site.Logo,
			"dark_mode":   h.cfg.Site.DarkMode,
			"base_url":    h.cfg.Site.BaseURL,
		},
	})
}

// UpdateSiteSettings updates site settings
// @Summary Update site settings
// @Description Update site configuration (title, description, logo)
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateSiteSettingsRequest true "Site settings"
// @Success 200 {object} handler.Response "Settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/site [put]
func (h *AdminHandler) UpdateSiteSettings(c *gin.Context) {
	var input struct {
		Title                 string            `json:"title"`
		TitleI18n             map[string]string `json:"title_i18n"`
		Description           string            `json:"description"`
		Logo                  string            `json:"logo"`
		DarkMode              string            `json:"dark_mode"`
		RedirectHomeToProfile *bool             `json:"redirect_home_to_profile"`
		BaseURL               *string           `json:"base_url"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate dark_mode value
	if input.DarkMode != "" && input.DarkMode != DarkModeSystem && input.DarkMode != DarkModeDark && input.DarkMode != DarkModeLight {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "暗色模式设置值无效，请选择 system、dark 或 light",
		})
		return
	}

	// Validate base_url format if provided
	if input.BaseURL != nil && *input.BaseURL != "" {
		baseURL := strings.TrimSuffix(*input.BaseURL, "/")
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "站点URL格式无效，必须以 http:// 或 https:// 开头",
			})
			return
		}
	}

	h.cfg.Site.Title = input.Title
	if input.TitleI18n != nil {
		h.cfg.Site.TitleI18n = input.TitleI18n
	}
	h.cfg.Site.Description = input.Description
	h.cfg.Site.Logo = input.Logo
	if input.DarkMode != "" {
		h.cfg.Site.DarkMode = input.DarkMode
	}
	if input.RedirectHomeToProfile != nil {
		h.cfg.Site.RedirectHomeToProfile = *input.RedirectHomeToProfile
	}
	if input.BaseURL != nil {
		// Remove trailing slash for consistency
		h.cfg.Site.BaseURL = strings.TrimSuffix(*input.BaseURL, "/")
	}

	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "网站设置已更新",
	})
}

// GetPaymentSettings returns payment settings
// @Summary Get payment settings
// @Description Get current payment gateway configuration
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Payment settings retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/payment [get]
func (h *AdminHandler) GetPaymentSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled":     h.cfg.Payment.Enabled,
			"demo_mode":   h.cfg.Payment.DemoMode,
			"api_url":     h.cfg.Payment.ApiURL,
			"merchant_id": h.cfg.Payment.MerchantID,
			"api_key":     maskSecret(h.cfg.Payment.ApiKey),
			"notify_url":  h.cfg.Payment.NotifyURL,
			"return_url":  h.cfg.Payment.ReturnURL,
		},
	})
}

// UpdatePaymentSettings updates payment settings
// @Summary Update payment settings
// @Description Update payment gateway configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdatePaymentSettingsRequest true "Payment settings"
// @Success 200 {object} handler.Response "Settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/payment [put]
func (h *AdminHandler) UpdatePaymentSettings(c *gin.Context) {
	var input struct {
		Enabled    bool   `json:"enabled"`
		DemoMode   bool   `json:"demo_mode"`
		ApiURL     string `json:"api_url"`
		MerchantID string `json:"merchant_id"`
		ApiKey     string `json:"api_key"`
		NotifyURL  string `json:"notify_url"`
		ReturnURL  string `json:"return_url"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.Payment.Enabled = input.Enabled
	h.cfg.Payment.DemoMode = input.DemoMode
	h.cfg.Payment.ApiURL = input.ApiURL
	h.cfg.Payment.MerchantID = input.MerchantID
	if input.ApiKey != "" && !isMasked(input.ApiKey) {
		h.cfg.Payment.ApiKey = input.ApiKey
	}
	h.cfg.Payment.NotifyURL = input.NotifyURL
	h.cfg.Payment.ReturnURL = input.ReturnURL

	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "支付设置已更新",
	})
}

// GetVIPLevels returns VIP level configurations
// @Summary Get VIP levels
// @Description Get all VIP level configurations
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "VIP levels retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/vip-levels [get]
func (h *AdminHandler) GetVIPLevels(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    h.cfg.VIPLevels,
	})
}

// UpdateVIPLevels updates VIP level configurations
// @Summary Update VIP levels
// @Description Update all VIP level configurations
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body UpdateVIPLevelsRequest true "VIP levels"
// @Success 200 {object} handler.Response "VIP levels updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/vip-levels [put]
func (h *AdminHandler) UpdateVIPLevels(c *gin.Context) {
	var input struct {
		VIPLevels []config.VIPLevelConfig `json:"vip_levels"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.VIPLevels = input.VIPLevels

	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "VIP等级配置已更新",
	})
}

// GetPublicVIPLevels returns VIP levels for public access (frontend)
// @Summary Get public VIP levels
// @Description Get VIP level configurations for frontend display
// @Tags public
// @Produce json
// @Success 200 {object} handler.Response "VIP levels retrieved"
// @Router /vip-levels [get]
func (h *AdminHandler) GetPublicVIPLevels(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    h.cfg.VIPLevels,
	})
}

// GetPublicSiteSettings returns site settings for public access
// @Summary Get public site settings
// @Description Get site configuration for frontend display
// @Tags public
// @Produce json
// @Success 200 {object} handler.Response "Site settings retrieved"
// @Router /site-settings [get]
func (h *AdminHandler) GetPublicSiteSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"title":             h.cfg.Site.Title,
			"description":       h.cfg.Site.Description,
			"logo":              h.cfg.Site.Logo,
			"dark_mode":         h.cfg.Site.DarkMode,
			"payment_enabled":   h.cfg.Payment.Enabled,
			"payment_demo_mode": h.cfg.Payment.DemoMode,
		},
	})
}

// GetProfileNavigation returns profile navigation settings
// @Summary Get profile navigation settings
// @Description Get profile page navigation configuration
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Profile navigation settings retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/profile-navigation [get]
func (h *AdminHandler) GetProfileNavigation(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    h.cfg.ProfileNavigation,
	})
}

// UpdateProfileNavigation updates profile navigation settings
// @Summary Update profile navigation settings
// @Description Update profile page navigation configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body config.ProfileNavigationConfig true "Profile navigation settings"
// @Success 200 {object} handler.Response "Profile navigation settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/profile-navigation [put]
func (h *AdminHandler) UpdateProfileNavigation(c *gin.Context) {
	var input config.ProfileNavigationConfig
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.ProfileNavigation = input

	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "个人中心导航配置已更新",
	})
}

// GetPublicProfileNavigation returns profile navigation for public access
// @Summary Get public profile navigation
// @Description Get profile navigation configuration for frontend display
// @Tags public
// @Produce json
// @Success 200 {object} handler.Response "Profile navigation retrieved"
// @Router /profile-navigation [get]
func (h *AdminHandler) GetPublicProfileNavigation(c *gin.Context) {
	// Only return visible items, sorted by order
	var visibleItems []config.ProfileNavItem
	for _, item := range h.cfg.ProfileNavigation.Items {
		if item.Visible {
			visibleItems = append(visibleItems, item)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    visibleItems,
	})
}

// ==================== Mobile Toolbar Settings ====================

// GetMobileToolbar returns mobile toolbar settings
// @Summary Get mobile toolbar settings
// @Description Get mobile bottom toolbar configuration
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Mobile toolbar settings retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/mobile-toolbar [get]
func (h *AdminHandler) GetMobileToolbar(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    h.cfg.MobileToolbar,
	})
}

// UpdateMobileToolbar updates mobile toolbar settings
// @Summary Update mobile toolbar settings
// @Description Update mobile bottom toolbar configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body config.MobileToolbarConfig true "Mobile toolbar settings"
// @Success 200 {object} handler.Response "Mobile toolbar settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/mobile-toolbar [put]
func (h *AdminHandler) UpdateMobileToolbar(c *gin.Context) {
	var input config.MobileToolbarConfig
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.MobileToolbar = input

	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "移动工具栏设置已更新",
	})
}

// GetPublicMobileToolbar returns mobile toolbar for public access
// @Summary Get public mobile toolbar
// @Description Get mobile toolbar configuration for frontend display
// @Tags public
// @Produce json
// @Success 200 {object} handler.Response "Mobile toolbar retrieved"
// @Router /mobile-toolbar [get]
func (h *AdminHandler) GetPublicMobileToolbar(c *gin.Context) {
	if !h.cfg.MobileToolbar.Enabled {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"enabled": false,
			"data":    []config.MobileNavItem{},
		})
		return
	}
	// Only return visible items, sorted by order
	var visibleItems []config.MobileNavItem
	for _, item := range h.cfg.MobileToolbar.Items {
		if item.Visible {
			visibleItems = append(visibleItems, item)
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"enabled": true,
		"data":    visibleItems,
	})
}

// ==================== Custom Settings (Global HTML/CSS, Footer) ====================

// CustomSettings represents custom HTML/CSS and footer settings
type CustomSettings struct {
	GlobalCSS  string `json:"global_css" example:"/* custom CSS */"`
	GlobalHTML string `json:"global_html" example:"<script>/* custom script */</script>"`
	FooterText string `json:"footer_text" example:"© 2024 Your Company"`
}

// GetCustomSettings returns custom settings
// @Summary Get custom settings
// @Description Get custom HTML/CSS and footer configuration
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Custom settings retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/custom [get]
func (h *AdminHandler) GetCustomSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"global_css":  h.cfg.Custom.GlobalCSS,
			"global_html": h.cfg.Custom.GlobalHTML,
			"footer_text": h.cfg.Custom.FooterText,
		},
	})
}

// UpdateCustomSettings updates custom settings
// @Summary Update custom settings
// @Description Update custom HTML/CSS and footer configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CustomSettings true "Custom settings"
// @Success 200 {object} handler.Response "Custom settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/custom [put]
func (h *AdminHandler) UpdateCustomSettings(c *gin.Context) {
	var input struct {
		GlobalCSS  string `json:"global_css"`
		GlobalHTML string `json:"global_html"`
		FooterText string `json:"footer_text"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	h.cfg.Custom.GlobalCSS = input.GlobalCSS
	h.cfg.Custom.GlobalHTML = input.GlobalHTML
	h.cfg.Custom.FooterText = input.FooterText

	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "自定义设置已更新",
	})
}

// GetPublicCustomSettings returns custom settings for public access
// @Summary Get public custom settings
// @Description Get custom HTML/CSS and footer configuration for frontend display
// @Tags public
// @Produce json
// @Success 200 {object} handler.Response "Custom settings retrieved"
// @Router /custom-settings [get]
func (h *AdminHandler) GetPublicCustomSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"global_css":  h.cfg.Custom.GlobalCSS,
			"global_html": h.cfg.Custom.GlobalHTML,
			"footer_text": h.cfg.Custom.FooterText,
		},
	})
}

// ==================== API Token Management ====================

// CreateAPITokenRequest represents API token creation request
type CreateAPITokenRequest struct {
	Name        string   `json:"name" binding:"required" example:"External API"`
	Permissions []string `json:"permissions" example:"['balance', 'vip']"`
	ExpiresIn   int      `json:"expires_in" example:"30"` // Days, 0 = never expires
}

// AdminAPITokens renders the admin API tokens page
func (h *AdminHandler) AdminAPITokens(c *gin.Context) {
	lang := c.GetString("lang")
	tokens, _ := h.apiTokenRepo.List()

	c.HTML(http.StatusOK, "admin_api_tokens.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"tokens":     tokens,
		"activeMenu": "api-tokens",
	})
}

// ListAPITokens returns all API tokens
// @Summary List API tokens
// @Description Get all API tokens
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "API tokens retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/api-tokens [get]
func (h *AdminHandler) ListAPITokens(c *gin.Context) {
	tokens, err := h.apiTokenRepo.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取API令牌列表失败",
		})
		return
	}

	// Mask token values for security
	for i := range tokens {
		tokens[i].Token = maskSecret(tokens[i].Token)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    tokens,
	})
}

// CreateAPIToken creates a new API token
// @Summary Create API token
// @Description Create a new API token for external access
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateAPITokenRequest true "API token creation request"
// @Success 200 {object} handler.Response "API token created"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/api-tokens [post]
func (h *AdminHandler) CreateAPIToken(c *gin.Context) {
	var input CreateAPITokenRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Convert permissions to JSON string
	permissions := strings.Join(input.Permissions, ",")

	var expiresAt *time.Time
	if input.ExpiresIn > 0 {
		t := time.Now().AddDate(0, 0, input.ExpiresIn)
		expiresAt = &t
	}

	token := &model.APIToken{
		Name:        input.Name,
		Token:       repository.GenerateToken(),
		Permissions: permissions,
		ExpiresAt:   expiresAt,
		IsActive:    true,
	}

	if err := h.apiTokenRepo.Create(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建API令牌失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "API令牌创建成功",
		"data":    token,
	})
}

// DeleteAPIToken deletes an API token
// @Summary Delete API token
// @Description Delete an API token
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "Token ID"
// @Success 200 {object} handler.Response "API token deleted"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/api-tokens/{id} [delete]
func (h *AdminHandler) DeleteAPIToken(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的令牌ID",
		})
		return
	}

	if err := h.apiTokenRepo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "删除API令牌失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "API令牌已删除",
	})
}

// ToggleAPIToken toggles an API token's active status
// @Summary Toggle API token status
// @Description Enable or disable an API token
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "Token ID"
// @Success 200 {object} handler.Response "API token status toggled"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/api-tokens/{id}/toggle [put]
func (h *AdminHandler) ToggleAPIToken(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的令牌ID",
		})
		return
	}

	token, err := h.apiTokenRepo.FindByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "令牌不存在",
		})
		return
	}

	token.IsActive = !token.IsActive
	if err := h.apiTokenRepo.Update(token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "更新令牌状态失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "令牌状态已更新",
		"data":    token,
	})
}

// ==================== Gift Card Management ====================

// CreateGiftCardRequest represents gift card creation request
type CreateGiftCardRequest struct {
	Amount      float64 `json:"amount" example:"100.00"`
	Count       int     `json:"count" example:"1"`
	ExpiresIn   int     `json:"expires_in" example:"30"` // Days, 0 = never expires
	Description string  `json:"description" example:"充值礼品卡"`
	VIPLevel    int     `json:"vip_level" example:"1"`   // VIP level to grant (0 = no VIP, balance only)
	VIPDays     int     `json:"vip_days" example:"30"`   // VIP duration in days (0 = permanent)
}

// AdminGiftCards renders the admin gift cards page
func (h *AdminHandler) AdminGiftCards(c *gin.Context) {
	lang := c.GetString("lang")
	cards, total, _ := h.giftCardRepo.List(1, 100)

	c.HTML(http.StatusOK, "admin_gift_cards.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"cards":      cards,
		"total":      total,
		"activeMenu": "gift-cards",
	})
}

// ListGiftCards returns all gift cards
// @Summary List gift cards
// @Description Get all gift cards with pagination
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Success 200 {object} handler.Response "Gift cards retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/gift-cards [get]
func (h *AdminHandler) ListGiftCards(c *gin.Context) {
	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	cards, total, err := h.giftCardRepo.List(page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取礼品卡列表失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"cards": cards,
			"total": total,
			"page":  page,
		},
	})
}

// CreateGiftCards creates new gift cards
// @Summary Create gift cards
// @Description Create one or multiple gift cards
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateGiftCardRequest true "Gift card creation request"
// @Success 200 {object} handler.Response "Gift cards created"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/gift-cards [post]
func (h *AdminHandler) CreateGiftCards(c *gin.Context) {
	var input CreateGiftCardRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate: either amount or VIP level must be set
	if input.Amount <= 0 && input.VIPLevel <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "金额或VIP等级至少需要设置一项",
		})
		return
	}

	// Validate VIP level if set
	if input.VIPLevel < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "VIP等级不能为负数",
		})
		return
	}

	// Validate VIP days if set
	if input.VIPDays < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "VIP天数不能为负数",
		})
		return
	}

	count := input.Count
	if count <= 0 {
		count = 1
	}
	if count > 100 {
		count = 100
	}

	var expiresAt *time.Time
	if input.ExpiresIn > 0 {
		t := time.Now().AddDate(0, 0, input.ExpiresIn)
		expiresAt = &t
	}

	cards, err := h.giftCardRepo.BatchCreate(input.Amount, count, expiresAt, input.Description, input.VIPLevel, input.VIPDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建礼品卡失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "礼品卡创建成功",
		"data":    cards,
	})
}

// DeleteGiftCard deletes a gift card
// @Summary Delete gift card
// @Description Delete a gift card
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param id path int true "Gift card ID"
// @Success 200 {object} handler.Response "Gift card deleted"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/gift-cards/{id} [delete]
func (h *AdminHandler) DeleteGiftCard(c *gin.Context) {
	idStr := c.Param("id")
	var id uint
	if _, err := parseUint(idStr, &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的礼品卡ID",
		})
		return
	}

	if err := h.giftCardRepo.Delete(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "删除礼品卡失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "礼品卡已删除",
	})
}

// ExportUnusedGiftCards exports all unused gift cards
// @Summary Export unused gift cards
// @Description Get all unused gift cards for export
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Unused gift cards retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to get gift cards"
// @Router /admin/gift-cards/export-unused [get]
func (h *AdminHandler) ExportUnusedGiftCards(c *gin.Context) {
	cards, err := h.giftCardRepo.ListUnused()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取未使用礼品卡失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"cards": cards,
			"total": len(cards),
		},
	})
}

// BatchDeleteGiftCardsRequest represents batch delete gift cards request
type BatchDeleteGiftCardsRequest struct {
	IDs []uint `json:"ids" binding:"required" example:"[1, 2, 3]"`
}

// BatchDeleteGiftCards deletes multiple gift cards
// @Summary Batch delete gift cards
// @Description Delete multiple gift cards by IDs
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BatchDeleteGiftCardsRequest true "Gift card IDs to delete"
// @Success 200 {object} handler.Response "Gift cards deleted"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to delete gift cards"
// @Router /admin/gift-cards/batch-delete [post]
func (h *AdminHandler) BatchDeleteGiftCards(c *gin.Context) {
	var input BatchDeleteGiftCardsRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if len(input.IDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请选择要删除的礼品卡",
		})
		return
	}

	deletedCount, err := h.giftCardRepo.BatchDelete(input.IDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "批量删除礼品卡失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "批量删除成功",
		"data": gin.H{
			"deleted_count": deletedCount,
		},
	})
}

// ==================== External API (Token Auth) ====================

// APIUpdateBalanceRequest represents external API balance update request
type APIUpdateBalanceRequest struct {
	UserID uint    `json:"user_id" binding:"required" example:"1"`
	Amount float64 `json:"amount" binding:"required" example:"100.00"`
	Reason string  `json:"reason" example:"API充值"`
}

// APISetVIPLevelRequest represents external API VIP level set request
type APISetVIPLevelRequest struct {
	UserID   uint `json:"user_id" binding:"required" example:"1"`
	VIPLevel int  `json:"vip_level" binding:"required" example:"3"`
}

// APIUpdateBalance updates a user's balance via API token
// @Summary Update user balance (API Token)
// @Description Update a user's balance using API token authentication
// @Tags external-api
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body APIUpdateBalanceRequest true "Balance update request"
// @Success 200 {object} handler.Response "Balance updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 403 {object} handler.Response "Forbidden - no permission"
// @Router /external/balance [post]
func (h *AdminHandler) APIUpdateBalance(c *gin.Context) {
	// Token is already validated by middleware
	token, exists := c.Get("api_token")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	apiToken := token.(*model.APIToken)
	
	// Check permission
	if !strings.Contains(apiToken.Permissions, "balance") && !strings.Contains(apiToken.Permissions, "all") {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "无权限执行此操作",
		})
		return
	}

	var input APIUpdateBalanceRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Get user's balance before update
	userBefore, err := h.userRepo.FindByID(input.UserID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}
	balanceBefore := userBefore.Balance

	// Prevent negative balance when reducing
	if input.Amount < 0 && balanceBefore+input.Amount < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "余额不足，无法执行此操作",
			"data": gin.H{
				"current_balance": balanceBefore,
				"requested_amount": input.Amount,
			},
		})
		return
	}

	user, err := h.userRepo.UpdateBalance(input.UserID, input.Amount)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	// Create balance log
	reason := input.Reason
	if reason == "" {
		reason = "API余额变更"
	}
	operatorID := apiToken.ID
	balanceLog := &model.BalanceLog{
		UserID:        input.UserID,
		Amount:        input.Amount,
		BalanceBefore: balanceBefore,
		BalanceAfter:  user.Balance,
		Type:          "api",
		Reason:        reason,
		OperatorID:    &operatorID,
		OperatorType:  "api_token",
	}
	h.balanceLogRepo.Create(balanceLog)

	// Update token last used time
	h.apiTokenRepo.UpdateLastUsed(apiToken.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "余额更新成功",
		"data": gin.H{
			"user_id": user.ID,
			"balance": user.Balance,
		},
	})
}

// APISetVIPLevel sets a user's VIP level via API token
// @Summary Set user VIP level (API Token)
// @Description Set a user's VIP level using API token authentication
// @Tags external-api
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body APISetVIPLevelRequest true "VIP level set request"
// @Success 200 {object} handler.Response "VIP level set"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 403 {object} handler.Response "Forbidden - no permission"
// @Router /external/vip-level [post]
func (h *AdminHandler) APISetVIPLevel(c *gin.Context) {
	// Token is already validated by middleware
	token, exists := c.Get("api_token")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	apiToken := token.(*model.APIToken)
	
	// Check permission
	if !strings.Contains(apiToken.Permissions, "vip") && !strings.Contains(apiToken.Permissions, "all") {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "无权限执行此操作",
		})
		return
	}

	var input APISetVIPLevelRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if input.VIPLevel < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "VIP等级不能为负数",
		})
		return
	}

	user, err := h.userRepo.SetVIPLevel(input.UserID, input.VIPLevel)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	// Update token last used time
	h.apiTokenRepo.UpdateLastUsed(apiToken.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "VIP等级设置成功",
		"data": gin.H{
			"user_id":   user.ID,
			"vip_level": user.VIPLevel,
		},
	})
}

// APIGetUser gets a user's info via API token
// @Summary Get user info (API Token)
// @Description Get a user's information using API token authentication
// @Tags external-api
// @Produce json
// @Security ApiKeyAuth
// @Param user_id query int true "User ID"
// @Success 200 {object} handler.Response "User info retrieved"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /external/user [get]
func (h *AdminHandler) APIGetUser(c *gin.Context) {
	// Token is already validated by middleware
	token, exists := c.Get("api_token")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	apiToken := token.(*model.APIToken)

	userIDStr := c.Query("user_id")
	var userID uint
	if _, err := parseUint(userIDStr, &userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的用户ID",
		})
		return
	}

	user, err := h.userRepo.FindByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	// Update token last used time
	h.apiTokenRepo.UpdateLastUsed(apiToken.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"id":            user.ID,
			"username":      user.Username,
			"email":         user.Email,
			"balance":       user.Balance,
			"vip_level":     user.VIPLevel,
			"vip_expire_at": user.VIPExpireAt,
			"is_active":     user.IsActive,
			"created_at":    user.CreatedAt,
		},
	})
}

// APISetPasswordRequest represents external API password set request
type APISetPasswordRequest struct {
	UserID   uint   `json:"user_id" binding:"required" example:"1"`
	Password string `json:"password" binding:"required" example:"newpassword123"`
}

// APISetPassword sets a user's password via API token
// @Summary Set user password (API Token)
// @Description Set a user's password using API token authentication. Requires 'password' or 'all' permission.
// @Tags external-api
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body APISetPasswordRequest true "Password set request"
// @Success 200 {object} handler.Response "Password set"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 403 {object} handler.Response "Forbidden - no permission"
// @Router /external/password [post]
func (h *AdminHandler) APISetPassword(c *gin.Context) {
	// Token is already validated by middleware
	token, exists := c.Get("api_token")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	apiToken := token.(*model.APIToken)

	// Check permission
	if !hasPermission(apiToken.Permissions, "password") {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "无权限执行此操作",
		})
		return
	}

	var input APISetPasswordRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate password
	if !utils.IsValidPassword(input.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "密码长度至少6个字符",
		})
		return
	}

	// Hash the new password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "密码加密失败",
		})
		return
	}

	// Reset the user's password
	user, err := h.userRepo.ResetPassword(input.UserID, hashedPassword)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	// Update token last used time
	h.apiTokenRepo.UpdateLastUsed(apiToken.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "密码设置成功",
		"data": gin.H{
			"user_id": user.ID,
		},
	})
}

// APISetVIPExpireAtRequest represents external API VIP expiration set request
type APISetVIPExpireAtRequest struct {
	UserID      uint   `json:"user_id" binding:"required" example:"1"`
	VIPExpireAt string `json:"vip_expire_at" example:"2025-12-31T23:59:59Z"` // ISO 8601 format, empty means clear
}

// APISetVIPExpireAt sets a user's VIP expiration time via API token
// @Summary Set user VIP expiration time (API Token)
// @Description Set a user's VIP expiration time using API token authentication. Requires 'vip' or 'all' permission.
// @Tags external-api
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body APISetVIPExpireAtRequest true "VIP expiration set request"
// @Success 200 {object} handler.Response "VIP expiration set"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 403 {object} handler.Response "Forbidden - no permission"
// @Router /external/vip-expire [post]
func (h *AdminHandler) APISetVIPExpireAt(c *gin.Context) {
	// Token is already validated by middleware
	token, exists := c.Get("api_token")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	apiToken := token.(*model.APIToken)

	// Check permission
	if !hasPermission(apiToken.Permissions, "vip") {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "无权限执行此操作",
		})
		return
	}

	var input APISetVIPExpireAtRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	var expireAt *time.Time
	if input.VIPExpireAt != "" {
		t, err := time.Parse(time.RFC3339, input.VIPExpireAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "VIP到期时间格式错误，请使用ISO 8601格式，例如：2025-12-31T23:59:59Z",
			})
			return
		}
		expireAt = &t
	}

	user, err := h.userRepo.SetVIPExpireAt(input.UserID, expireAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"message": "用户不存在或更新失败",
		})
		return
	}

	// Update token last used time
	h.apiTokenRepo.UpdateLastUsed(apiToken.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "VIP到期时间设置成功",
		"data": gin.H{
			"user_id":       user.ID,
			"vip_level":     user.VIPLevel,
			"vip_expire_at": user.VIPExpireAt,
		},
	})
}

// CreateUserRequest represents user creation request for both admin and external API
type CreateUserRequest struct {
	ID          *uint   `json:"id" example:"100"`                           // Optional: force specific ID
	Email       string  `json:"email" binding:"required" example:"user@example.com"`
	Username    string  `json:"username" binding:"required" example:"newuser"`
	Password    string  `json:"password" binding:"required" example:"password123"`
	DisplayName string  `json:"display_name" example:"New User"`
	Balance     float64 `json:"balance" example:"100.00"`                   // Optional: initial balance
	VIPLevel    int     `json:"vip_level" example:"1"`                      // Optional: VIP level
	VIPExpireAt string  `json:"vip_expire_at" example:"2025-12-31T23:59:59Z"` // Optional: VIP expiration (ISO 8601)
	IsActive    *bool   `json:"is_active" example:"true"`                   // Optional: active status, default true
}

// APICreateUserRequest is a type alias for external API endpoint documentation
type APICreateUserRequest = CreateUserRequest

// AdminCreateUserRequest is a type alias for admin API endpoint documentation
type AdminCreateUserRequest = CreateUserRequest

// APICreateUser creates a new user via API token
// @Summary Create user (API Token)
// @Description Create a new user with specific parameters using API token authentication. Requires 'user' or 'all' permission.
// @Tags external-api
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body APICreateUserRequest true "User creation request"
// @Success 200 {object} handler.Response "User created"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 403 {object} handler.Response "Forbidden - no permission"
// @Failure 409 {object} handler.Response "Conflict - user ID/email/username already exists"
// @Router /external/user [post]
func (h *AdminHandler) APICreateUser(c *gin.Context) {
	// Token is already validated by middleware
	token, exists := c.Get("api_token")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未授权",
		})
		return
	}

	apiToken := token.(*model.APIToken)

	// Check permission
	if !hasPermission(apiToken.Permissions, "user") {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "无权限执行此操作",
		})
		return
	}

	var input APICreateUserRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate email format
	if !utils.IsValidEmail(input.Email) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的邮箱地址",
		})
		return
	}

	// Validate username
	if !utils.IsValidUsername(input.Username) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "用户名只能包含字母、数字和下划线，长度2-32个字符",
		})
		return
	}

	// Validate password
	if !utils.IsValidPassword(input.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "密码长度至少6个字符",
		})
		return
	}

	// Check if specific ID is requested
	if input.ID != nil {
		if h.userRepo.ExistsByID(*input.ID) {
			c.JSON(http.StatusConflict, gin.H{
				"success": false,
				"message": "用户ID已存在",
			})
			return
		}
	}

	// Check if email exists
	if h.userRepo.ExistsByEmail(input.Email) {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "邮箱已被注册",
		})
		return
	}

	// Check if username exists
	if h.userRepo.ExistsByUsername(input.Username) {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "用户名已被使用",
		})
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "密码加密失败",
		})
		return
	}

	// Parse VIP expiration time
	var vipExpireAt *time.Time
	if input.VIPExpireAt != "" {
		t, err := time.Parse(time.RFC3339, input.VIPExpireAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "VIP到期时间格式错误，请使用ISO 8601格式，例如：2025-12-31T23:59:59Z",
			})
			return
		}
		vipExpireAt = &t
	}

	// Create user
	displayName := input.DisplayName
	if displayName == "" {
		displayName = input.Username
	}

	isActive := true
	if input.IsActive != nil {
		isActive = *input.IsActive
	}

	user := &model.User{
		Email:       input.Email,
		Username:    input.Username,
		Password:    hashedPassword,
		DisplayName: displayName,
		IsActive:    isActive,
		Balance:     input.Balance,
		VIPLevel:    input.VIPLevel,
		VIPExpireAt: vipExpireAt,
	}

	// Set specific ID if provided
	if input.ID != nil {
		user.ID = *input.ID
	}

	if err := h.userRepo.CreateWithID(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建用户失败: " + err.Error(),
		})
		return
	}

	// Update token last used time
	h.apiTokenRepo.UpdateLastUsed(apiToken.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户创建成功",
		"data": gin.H{
			"id":            user.ID,
			"username":      user.Username,
			"email":         user.Email,
			"display_name":  user.DisplayName,
			"balance":       user.Balance,
			"vip_level":     user.VIPLevel,
			"vip_expire_at": user.VIPExpireAt,
			"is_active":     user.IsActive,
			"created_at":    user.CreatedAt,
		},
	})
}

// AdminCreateUser creates a new user via admin panel
// @Summary Create user (Admin)
// @Description Create a new user with specific parameters via admin panel
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AdminCreateUserRequest true "User creation request"
// @Success 200 {object} handler.Response "User created"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 409 {object} handler.Response "Conflict - user ID/email/username already exists"
// @Router /admin/users [post]
func (h *AdminHandler) AdminCreateUser(c *gin.Context) {
	var input AdminCreateUserRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate email format
	if !utils.IsValidEmail(input.Email) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的邮箱地址",
		})
		return
	}

	// Validate username
	if !utils.IsValidUsername(input.Username) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "用户名只能包含字母、数字和下划线，长度2-32个字符",
		})
		return
	}

	// Validate password
	if !utils.IsValidPassword(input.Password) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "密码长度至少6个字符",
		})
		return
	}

	// Check if specific ID is requested
	if input.ID != nil {
		if h.userRepo.ExistsByID(*input.ID) {
			c.JSON(http.StatusConflict, gin.H{
				"success": false,
				"message": "用户ID已存在",
			})
			return
		}
	}

	// Check if email exists
	if h.userRepo.ExistsByEmail(input.Email) {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "邮箱已被注册",
		})
		return
	}

	// Check if username exists
	if h.userRepo.ExistsByUsername(input.Username) {
		c.JSON(http.StatusConflict, gin.H{
			"success": false,
			"message": "用户名已被使用",
		})
		return
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "密码加密失败",
		})
		return
	}

	// Parse VIP expiration time
	var vipExpireAt *time.Time
	if input.VIPExpireAt != "" {
		t, err := time.Parse(time.RFC3339, input.VIPExpireAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "VIP到期时间格式错误，请使用ISO 8601格式，例如：2025-12-31T23:59:59Z",
			})
			return
		}
		vipExpireAt = &t
	}

	// Create user
	displayName := input.DisplayName
	if displayName == "" {
		displayName = input.Username
	}

	isActive := true
	if input.IsActive != nil {
		isActive = *input.IsActive
	}

	user := &model.User{
		Email:       input.Email,
		Username:    input.Username,
		Password:    hashedPassword,
		DisplayName: displayName,
		IsActive:    isActive,
		Balance:     input.Balance,
		VIPLevel:    input.VIPLevel,
		VIPExpireAt: vipExpireAt,
	}

	// Set specific ID if provided
	if input.ID != nil {
		user.ID = *input.ID
	}

	if err := h.userRepo.CreateWithID(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建用户失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "用户创建成功",
		"data": gin.H{
			"id":            user.ID,
			"username":      user.Username,
			"email":         user.Email,
			"display_name":  user.DisplayName,
			"balance":       user.Balance,
			"vip_level":     user.VIPLevel,
			"vip_expire_at": user.VIPExpireAt,
			"is_active":     user.IsActive,
			"created_at":    user.CreatedAt,
		},
	})
}

// ==================== Login Protection Settings ====================

// LoginProtectionSettings represents login protection settings
type LoginProtectionSettings struct {
	Enabled       bool `json:"enabled" example:"true"`
	MaxAttempts   int  `json:"max_attempts" example:"5"`
	FreezeSeconds int  `json:"freeze_seconds" example:"300"`
	WindowSeconds int  `json:"window_seconds" example:"600"`
}

// GetLoginProtectionSettings returns login protection settings
// @Summary Get login protection settings
// @Description Get current login protection configuration
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response{data=LoginProtectionSettings} "Login protection settings retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/settings/login-protection [get]
func (h *AdminHandler) GetLoginProtectionSettings(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled":        h.cfg.LoginProtection.Enabled,
			"max_attempts":   h.cfg.LoginProtection.MaxAttempts,
			"freeze_seconds": h.cfg.LoginProtection.FreezeSeconds,
			"window_seconds": h.cfg.LoginProtection.WindowSeconds,
		},
	})
}

// UpdateLoginProtectionSettings updates login protection settings
// @Summary Update login protection settings
// @Description Update login protection configuration
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body LoginProtectionSettings true "Login protection settings"
// @Success 200 {object} handler.Response "Settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/login-protection [put]
func (h *AdminHandler) UpdateLoginProtectionSettings(c *gin.Context) {
	var input struct {
		Enabled       bool `json:"enabled"`
		MaxAttempts   int  `json:"max_attempts"`
		FreezeSeconds int  `json:"freeze_seconds"`
		WindowSeconds int  `json:"window_seconds"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate input
	if input.MaxAttempts < 1 {
		input.MaxAttempts = 1
	}
	if input.FreezeSeconds < 1 {
		input.FreezeSeconds = 1
	}
	if input.WindowSeconds < 1 {
		input.WindowSeconds = 1
	}

	h.cfg.LoginProtection.Enabled = input.Enabled
	h.cfg.LoginProtection.MaxAttempts = input.MaxAttempts
	h.cfg.LoginProtection.FreezeSeconds = input.FreezeSeconds
	h.cfg.LoginProtection.WindowSeconds = input.WindowSeconds

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "登录保护设置已更新",
	})
}

// UpdateRegistrationProtectionSettings updates registration rate limiting settings
// @Summary Update registration rate limiting settings
// @Description Update registration protection configuration (IP-based rate limiting)
// @Tags admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Settings updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 500 {object} handler.Response "Failed to save settings"
// @Router /admin/settings/registration-protection [put]
func (h *AdminHandler) UpdateRegistrationProtectionSettings(c *gin.Context) {
	var input struct {
		Enabled          bool `json:"enabled"`
		MaxRegistrations int  `json:"max_registrations"`
		WindowSeconds    int  `json:"window_seconds"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate input
	if input.MaxRegistrations < 1 {
		input.MaxRegistrations = 1
	}
	if input.WindowSeconds < 1 {
		input.WindowSeconds = 1
	}

	h.cfg.RegistrationProtection.Enabled = input.Enabled
	h.cfg.RegistrationProtection.MaxRegistrations = input.MaxRegistrations
	h.cfg.RegistrationProtection.WindowSeconds = input.WindowSeconds

	// Save to file
	if err := config.Save("config.json"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "保存配置失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "注册限制设置已更新",
	})
}

// ==================== Login Logs ====================

// AdminLoginLogs renders the admin login logs page
func (h *AdminHandler) AdminLoginLogs(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "admin_login_logs.html", gin.H{
		"lang":       lang,
		"config":     h.cfg,
		"activeMenu": "login-logs",
	})
}

// ListLoginLogs returns login logs with pagination and optional filters
// @Summary List login logs
// @Description Get login logs with pagination and optional filters
// @Tags admin
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param page_size query int false "Page size" default(20)
// @Param ip query string false "Filter by IP address"
// @Param success query string false "Filter by success status (true/false)"
// @Param username query string false "Filter by username"
// @Param user_id query int false "Filter by user ID"
// @Success 200 {object} handler.Response "Login logs retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /admin/login-logs [get]
func (h *AdminHandler) ListLoginLogs(c *gin.Context) {
	if h.loginLogRepo == nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"logs":      []model.LoginLog{},
				"total":     0,
				"page":      1,
				"page_size": 20,
			},
		})
		return
	}

	page := 1
	pageSize := 20

	if p := c.Query("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := c.Query("page_size"); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 && v <= 100 {
			pageSize = v
		}
	}

	ip := c.Query("ip")
	username := c.Query("username")

	var success *bool
	if s := c.Query("success"); s != "" {
		val := s == "true"
		success = &val
	}

	var userID *uint
	if uid := c.Query("user_id"); uid != "" {
		var id uint
		if _, err := parseUint(uid, &id); err == nil {
			userID = &id
		}
	}

	logs, total, err := h.loginLogRepo.List(page, pageSize, ip, success, username, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "获取登录日志失败",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"logs":      logs,
			"total":     total,
			"page":      page,
			"page_size": pageSize,
		},
	})
}
