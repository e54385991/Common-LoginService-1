package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/i18n"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/e54385991/Common-LoginService/pkg/utils"
	"github.com/gin-gonic/gin"
)

// Response is a generic API response
type Response struct {
	Success bool        `json:"success" example:"true"`
	Message string      `json:"message,omitempty" example:"操作成功"`
	Data    interface{} `json:"data,omitempty"`
}

// RegisterRequest represents registration request body
type RegisterRequest struct {
	Email           string `json:"email" binding:"required,email" example:"user@example.com"`
	Username        string `json:"username" binding:"required" example:"johndoe"`
	Password        string `json:"password" binding:"required" example:"password123"`
	DisplayName     string `json:"display_name" example:"John Doe"`
	CaptchaID       string `json:"captcha_id" example:"abc123"`
	CaptchaPosition int    `json:"captcha_position" example:"150"`
}

// LoginRequest represents login request body
type LoginRequest struct {
	Email           string `json:"email" binding:"required" example:"user@example.com"`
	Password        string `json:"password" binding:"required" example:"password123"`
	CaptchaID       string `json:"captcha_id" example:"abc123"`
	CaptchaPosition int    `json:"captcha_position" example:"150"`
}

// UpdateProfileRequest represents profile update request body
type UpdateProfileRequest struct {
	DisplayName string `json:"display_name" example:"John Doe"`
	Avatar      string `json:"avatar" example:"https://example.com/avatar.jpg"`
}

// ForgotPasswordRequest represents forgot password request body
type ForgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email" example:"user@example.com"`
}

// ResetPasswordRequest represents reset password request body
type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required" example:"reset-token-abc123"`
	NewPassword string `json:"new_password" binding:"required" example:"newpassword123"`
}

// ValidateTokenRequest represents token validation request body
type ValidateTokenRequest struct {
	Token string `json:"token" binding:"required" example:"jwt-token-xyz"`
}

// ValidateTokenResponse represents token validation response
type ValidateTokenResponse struct {
	Valid bool        `json:"valid" example:"true"`
	User  *model.User `json:"user"`
}

// GoogleOAuthStatusResponse represents Google OAuth status response
type GoogleOAuthStatusResponse struct {
	Enabled  bool   `json:"enabled" example:"true"`
	ClientID string `json:"client_id" example:"your-client-id.apps.googleusercontent.com"`
}

// AuthHandler handles authentication requests
type AuthHandler struct {
	authService    *service.AuthService
	emailService   *service.EmailService
	captchaService *service.CaptchaService
	cfg            *config.Config
	userRepo       interface {
		FindByID(id uint) (*model.User, error)
		UpdateBalance(id uint, amount float64) (*model.User, error)
		SetVIPLevel(id uint, level int) (*model.User, error)
		SetVIPLevelWithDuration(id uint, level int, durationDays int) (*model.User, error)
		SetVIPLevelWithUpgrade(id uint, level int, durationDays int, oldPrice float64, newPrice float64) (*model.User, int, error)
		RenewVIPLevel(id uint, level int, durationDays int) (*model.User, error)
		SetEmailVerified(id uint, verified bool) (*model.User, error)
		UpdateEmail(id uint, email string) (*model.User, error)
		ExistsByEmail(email string) bool
	}
	giftCardRepo interface {
		Redeem(code string, userID uint) (*model.GiftCard, error)
		FindByCode(code string) (*model.GiftCard, error)
	}
	balanceLogRepo interface {
		Create(log *model.BalanceLog) error
	}
	emailVerificationRepo interface {
		Create(userID uint, email string) (*model.EmailVerificationToken, error)
		FindByToken(token string) (*model.EmailVerificationToken, error)
		FindByUserIDAndCode(userID uint, code string) (*model.EmailVerificationToken, error)
		MarkUsed(id uint) error
		CanSendVerificationEmail(userID uint) (bool, int, error)
	}
	registrationLogRepo interface {
		Create(log *model.RegistrationLog) error
		CanRegister(ip string, maxRegistrations int, windowSeconds int) (bool, int64, error)
	}
}

// NewAuthHandler creates a new AuthHandler
func NewAuthHandler(authService *service.AuthService, emailService *service.EmailService, captchaService *service.CaptchaService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		authService:    authService,
		emailService:   emailService,
		captchaService: captchaService,
		cfg:            cfg,
	}
}

// SetUserRepo sets the user repository for AuthHandler
func (h *AuthHandler) SetUserRepo(userRepo interface {
	FindByID(id uint) (*model.User, error)
	UpdateBalance(id uint, amount float64) (*model.User, error)
	SetVIPLevel(id uint, level int) (*model.User, error)
	SetVIPLevelWithDuration(id uint, level int, durationDays int) (*model.User, error)
	SetVIPLevelWithUpgrade(id uint, level int, durationDays int, oldPrice float64, newPrice float64) (*model.User, int, error)
	RenewVIPLevel(id uint, level int, durationDays int) (*model.User, error)
	SetEmailVerified(id uint, verified bool) (*model.User, error)
	UpdateEmail(id uint, email string) (*model.User, error)
	ExistsByEmail(email string) bool
}) {
	h.userRepo = userRepo
}

// SetGiftCardRepo sets the gift card repository for AuthHandler
func (h *AuthHandler) SetGiftCardRepo(giftCardRepo interface {
	Redeem(code string, userID uint) (*model.GiftCard, error)
	FindByCode(code string) (*model.GiftCard, error)
}) {
	h.giftCardRepo = giftCardRepo
}

// SetBalanceLogRepo sets the balance log repository for AuthHandler
func (h *AuthHandler) SetBalanceLogRepo(balanceLogRepo interface {
	Create(log *model.BalanceLog) error
}) {
	h.balanceLogRepo = balanceLogRepo
}

// SetEmailVerificationRepo sets the email verification repository for AuthHandler
func (h *AuthHandler) SetEmailVerificationRepo(emailVerificationRepo interface {
	Create(userID uint, email string) (*model.EmailVerificationToken, error)
	FindByToken(token string) (*model.EmailVerificationToken, error)
	FindByUserIDAndCode(userID uint, code string) (*model.EmailVerificationToken, error)
	MarkUsed(id uint) error
	CanSendVerificationEmail(userID uint) (bool, int, error)
}) {
	h.emailVerificationRepo = emailVerificationRepo
}

// SetRegistrationLogRepo sets the registration log repository for AuthHandler
func (h *AuthHandler) SetRegistrationLogRepo(registrationLogRepo interface {
	Create(log *model.RegistrationLog) error
	CanRegister(ip string, maxRegistrations int, windowSeconds int) (bool, int64, error)
}) {
	h.registrationLogRepo = registrationLogRepo
}

// isSecureRequest checks if the request is over HTTPS
func isSecureRequest(c *gin.Context) bool {
	return c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https"
}

// isValidCallbackURL validates the callback URL to prevent open redirect attacks.
// It checks that the URL has a valid scheme (http/https) and is parseable.
// Returns false for empty strings, which callers handle by clearing the callback.
// For stricter validation, you could also check against an allowlist of domains.
func isValidCallbackURL(callbackURL string) bool {
	if callbackURL == "" {
		return false
	}
	parsedURL, err := url.Parse(callbackURL)
	if err != nil {
		return false
	}
	// Only allow http and https schemes
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}
	// Ensure a host is present
	if parsedURL.Host == "" {
		return false
	}
	return true
}

// getSiteTitle returns the site title for the given language, falling back to default title
func (h *AuthHandler) getSiteTitle(lang string) string {
	if h.cfg.Site.TitleI18n != nil {
		if title, ok := h.cfg.Site.TitleI18n[lang]; ok && title != "" {
			return title
		}
	}
	return h.cfg.Site.Title
}

// translateError translates service errors with i18n support
// Detects PasswordValidationError and translates it, otherwise returns the original error message
func translateError(err error, lang string) string {
	var pwErr *utils.PasswordValidationError
	if errors.As(err, &pwErr) {
		msg := i18n.T(lang, pwErr.Code)
		if pwErr.Code == "error.password_too_short" && pwErr.MinLength > 0 {
			return fmt.Sprintf(msg, pwErr.MinLength)
		}
		return msg
	}
	return err.Error()
}

// Register handles user registration
// @Summary User registration
// @Description Register a new user with email, username and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body handler.RegisterRequest true "Registration request"
// @Success 200 {object} handler.Response{data=service.AuthResponse} "Registration successful"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 403 {object} handler.Response "Registration disabled"
// @Failure 429 {object} handler.Response "Too many registrations from this IP"
// @Router /auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	// Check if registration is enabled
	if !h.cfg.Access.RegistrationEnabled {
		message := "注册功能已关闭"
		if h.cfg.Access.RegistrationMessage != "" {
			message = h.cfg.Access.RegistrationMessage
		}
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": message,
		})
		return
	}

	clientIP := c.ClientIP()

	// Check registration rate limit if enabled
	if h.cfg.RegistrationProtection.Enabled && h.registrationLogRepo != nil && clientIP != "" {
		canRegister, remaining, err := h.registrationLogRepo.CanRegister(
			clientIP,
			h.cfg.RegistrationProtection.MaxRegistrations,
			h.cfg.RegistrationProtection.WindowSeconds,
		)
		if err == nil && !canRegister {
			windowMinutes := h.cfg.RegistrationProtection.WindowSeconds / 60
			c.JSON(http.StatusTooManyRequests, gin.H{
				"success":   false,
				"message":   "注册过于频繁，请稍后再试",
				"remaining": remaining,
				"window":    windowMinutes,
			})
			return
		}
	}

	var input struct {
		service.RegisterInput
		CaptchaID       string `json:"captcha_id"`
		CaptchaPosition int    `json:"captcha_position"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Verify captcha if enabled
	if h.cfg.Captcha.Enabled {
		if input.CaptchaID == "" || !h.captchaService.IsVerified(input.CaptchaID) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "请先完成验证码验证",
			})
			return
		}
	}

	response, err := h.authService.Register(&input.RegisterInput)
	if err != nil {
		lang := c.GetString("lang")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": translateError(err, lang),
		})
		return
	}

	// Log successful registration for rate limiting
	if h.registrationLogRepo != nil && clientIP != "" {
		regLog := &model.RegistrationLog{
			IP:      clientIP,
			UserID:  &response.User.ID,
			Success: true,
		}
		if err := h.registrationLogRepo.Create(regLog); err != nil {
			log.Printf("Failed to log registration for rate limiting: %v", err)
		}
	}

	// Set cookie (secure flag based on request protocol)
	c.SetCookie("token", response.Token, h.cfg.JWT.ExpireHour*3600, "/", "", isSecureRequest(c), true)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "注册成功",
		"data":    response,
	})
}

// Login handles user login
// @Summary User login
// @Description Authenticate a user with email and password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body handler.LoginRequest true "Login request"
// @Success 200 {object} handler.Response{data=service.AuthResponse} "Login successful"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Invalid credentials"
// @Failure 403 {object} handler.Response "Login disabled"
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	// Check if login is enabled
	if !h.cfg.Access.LoginEnabled {
		message := "登录功能已关闭"
		if h.cfg.Access.LoginMessage != "" {
			message = h.cfg.Access.LoginMessage
		}
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": message,
		})
		return
	}

	var input struct {
		service.LoginInput
		CaptchaID       string `json:"captcha_id"`
		CaptchaPosition int    `json:"captcha_position"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Verify captcha if enabled
	if h.cfg.Captcha.Enabled {
		if input.CaptchaID == "" || !h.captchaService.IsVerified(input.CaptchaID) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "请先完成验证码验证",
			})
			return
		}
	}

	// Use LoginWithContext to pass IP and User-Agent for login protection
	loginInput := &service.LoginInputWithContext{
		LoginInput: input.LoginInput,
		IP:         c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	}

	response, err := h.authService.LoginWithContext(loginInput)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// Set cookie (secure flag based on request protocol)
	c.SetCookie("token", response.Token, h.cfg.JWT.ExpireHour*3600, "/", "", isSecureRequest(c), true)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "登录成功",
		"data":    response,
	})
}

// Logout handles user logout
// @Summary User logout
// @Description Log out the current user by clearing the token cookie and invalidating the session
// @Tags auth
// @Produce json
// @Success 200 {object} handler.Response "Logout successful"
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get token from cookie or header
	tokenString := ""
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			tokenString = parts[1]
		}
	}
	if tokenString == "" {
		tokenString, _ = c.Cookie("token")
	}

	// Invalidate session if token exists
	if tokenString != "" {
		h.authService.Logout(tokenString)
	}

	// Clear cookie (secure flag based on request protocol)
	c.SetCookie("token", "", -1, "/", "", isSecureRequest(c), true)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "登出成功",
	})
}

// GetProfile returns the current user's profile
// @Summary Get user profile
// @Description Get the current authenticated user's profile
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response{data=model.User} "User profile"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/profile [get]
func (h *AuthHandler) GetProfile(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "未登录",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    user,
	})
}

// UpdateProfile updates the current user's profile
// @Summary Update user profile
// @Description Update the current authenticated user's profile (display name, avatar)
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body handler.UpdateProfileRequest true "Profile update request"
// @Success 200 {object} handler.Response{data=model.User} "Profile updated"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/profile [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := c.GetUint("userID")

	var input struct {
		DisplayName string `json:"display_name"`
		Avatar      string `json:"avatar"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	user, err := h.authService.UpdateProfile(userID, input.DisplayName, input.Avatar)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "更新成功",
		"data":    user,
	})
}

// ChangePasswordRequest represents change password request body
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required" example:"oldpassword123"`
	NewPassword string `json:"new_password" binding:"required" example:"newpassword123"`
}

// ChangePassword changes the current user's password
// @Summary Change password
// @Description Change the current authenticated user's password
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body handler.ChangePasswordRequest true "Change password request"
// @Success 200 {object} handler.Response "Password changed"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID := c.GetUint("userID")

	var input ChangePasswordRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if err := h.authService.ChangePassword(userID, input.OldPassword, input.NewPassword); err != nil {
		lang := c.GetString("lang")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": translateError(err, lang),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "密码修改成功",
	})
}

// ForgotPassword initiates password reset
// @Summary Forgot password
// @Description Initiate password reset by sending a reset email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body handler.ForgotPasswordRequest true "Forgot password request"
// @Success 200 {object} handler.Response "Reset email sent"
// @Failure 400 {object} handler.Response "Bad request"
// @Router /auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var input struct {
		Email string `json:"email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请提供有效的邮箱地址",
		})
		return
	}

	token, err := h.authService.RequestPasswordReset(input.Email)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	// Get base URL from config or request
	baseURL := utils.GetBaseURL(c, h.cfg.Site.BaseURL)

	if err := h.emailService.SendPasswordResetEmail(input.Email, token, baseURL); err != nil {
		// If email fails, log the error but return success for security
		// (don't reveal whether email exists)
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "如果该邮箱已注册，您将收到重置密码的邮件",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "重置密码邮件已发送，请检查您的邮箱",
	})
}

// ResetPassword resets the user's password
// @Summary Reset password
// @Description Reset user password using the reset token from email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body handler.ResetPasswordRequest true "Reset password request"
// @Success 200 {object} handler.Response "Password reset successful"
// @Failure 400 {object} handler.Response "Bad request or invalid token"
// @Router /auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var input struct {
		Token       string `json:"token" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if err := h.authService.ResetPassword(input.Token, input.NewPassword); err != nil {
		lang := c.GetString("lang")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": translateError(err, lang),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "密码重置成功，请重新登录",
	})
}

// ValidateToken validates a JWT token
// @Summary Validate token
// @Description Validate a JWT token and return user info
// @Tags auth
// @Accept json
// @Produce json
// @Param request body handler.ValidateTokenRequest true "Token validation request"
// @Success 200 {object} handler.Response{data=handler.ValidateTokenResponse} "Token is valid"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Invalid token"
// @Router /auth/validate [post]
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	var input struct {
		Token string `json:"token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	user, err := h.authService.ValidateToken(input.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"valid": true,
			"user":  user,
		},
	})
}

// GetGoogleOAuthStatus returns Google OAuth status
// @Summary Get Google OAuth status
// @Description Check if Google OAuth is enabled and get client ID
// @Tags auth
// @Produce json
// @Success 200 {object} handler.Response{data=handler.GoogleOAuthStatusResponse} "Google OAuth status"
// @Router /auth/google/status [get]
func (h *AuthHandler) GetGoogleOAuthStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled":   h.cfg.GoogleOAuth.Enabled,
			"client_id": h.cfg.GoogleOAuth.ClientID,
		},
	})
}

// --- Page Handlers ---

// LoginPage renders the login page
func (h *AuthHandler) LoginPage(c *gin.Context) {
	// Check for redirect parameter and validate it
	redirectURL := c.Query("redirect")
	validRedirect := isValidCallbackURL(redirectURL)
	if !validRedirect {
		redirectURL = ""
	}

	// Check if already logged in
	if token, _ := c.Cookie("token"); token != "" {
		if _, err := h.authService.ValidateToken(token); err == nil {
			// If there's a valid redirect parameter, process callback with signed URL
			if redirectURL != "" && h.cfg.SignedURL.Enabled {
				user, err := h.authService.ValidateToken(token)
				if err == nil {
					// Build signed callback URL with user data
					userData := &utils.SimplifiedSignedData{
						UID:       user.ID,
						VIPLevel:  user.VIPLevel,
						Balance:   user.Balance,
						Timestamp: time.Now().Unix(),
					}

					signedURL, err := utils.BuildSimplifiedSignedCallbackURL(redirectURL, h.cfg.SignedURL.Secret, userData)
					if err == nil {
						c.Redirect(http.StatusFound, signedURL)
						return
					}
				}
			}
			// No redirect or signed URL disabled, go to profile
			c.Redirect(http.StatusFound, "/profile")
			return
		}
	}

	lang := c.GetString("lang")
	
	// Prepare login disabled message
	loginDisabledMessage := "登录功能已关闭"
	if h.cfg.Access.LoginMessage != "" {
		loginDisabledMessage = h.cfg.Access.LoginMessage
	}
	
	c.HTML(http.StatusOK, "login.html", gin.H{
		"lang":                 lang,
		"googleOAuthEnabled":   h.cfg.GoogleOAuth.Enabled,
		"googleClientID":       h.cfg.GoogleOAuth.ClientID,
		"steamOAuthEnabled":    h.cfg.SteamOAuth.Enabled,
		"discordOAuthEnabled":  h.cfg.DiscordOAuth.Enabled,
		"captchaEnabled":       h.cfg.Captcha.Enabled,
		"redirect":             redirectURL,
		"loginEnabled":         h.cfg.Access.LoginEnabled,
		"loginDisabledMessage": loginDisabledMessage,
		"allowEmailLogin":      h.cfg.Access.AllowEmailLogin,
		"allowUsernameLogin":   h.cfg.Access.AllowUsernameLogin,
		"custom":               h.cfg.Custom,
		"darkMode":             h.cfg.Site.DarkMode,
	})
}

// RegisterPage renders the registration page
func (h *AuthHandler) RegisterPage(c *gin.Context) {
	lang := c.GetString("lang")
	// Validate the redirect URL
	redirectURL := c.Query("redirect")
	if !isValidCallbackURL(redirectURL) {
		redirectURL = ""
	}
	
	// Prepare registration disabled message
	registrationDisabledMessage := "注册功能已关闭"
	if h.cfg.Access.RegistrationMessage != "" {
		registrationDisabledMessage = h.cfg.Access.RegistrationMessage
	}
	
	c.HTML(http.StatusOK, "register.html", gin.H{
		"lang":                        lang,
		"googleOAuthEnabled":          h.cfg.GoogleOAuth.Enabled,
		"googleClientID":              h.cfg.GoogleOAuth.ClientID,
		"steamOAuthEnabled":           h.cfg.SteamOAuth.Enabled,
		"discordOAuthEnabled":         h.cfg.DiscordOAuth.Enabled,
		"captchaEnabled":              h.cfg.Captcha.Enabled,
		"redirect":                    redirectURL,
		"registrationEnabled":         h.cfg.Access.RegistrationEnabled,
		"registrationDisabledMessage": registrationDisabledMessage,
		"custom":                      h.cfg.Custom,
		"darkMode":                    h.cfg.Site.DarkMode,
	})
}

// ForgotPasswordPage renders the forgot password page
func (h *AuthHandler) ForgotPasswordPage(c *gin.Context) {
	lang := c.GetString("lang")
	c.HTML(http.StatusOK, "forgot_password.html", gin.H{
		"lang":     lang,
		"custom":   h.cfg.Custom,
		"darkMode": h.cfg.Site.DarkMode,
	})
}

// ResetPasswordPage renders the reset password page
func (h *AuthHandler) ResetPasswordPage(c *gin.Context) {
	lang := c.GetString("lang")
	token := c.Query("token")
	c.HTML(http.StatusOK, "reset_password.html", gin.H{
		"lang":     lang,
		"token":    token,
		"custom":   h.cfg.Custom,
		"darkMode": h.cfg.Site.DarkMode,
	})
}

// getVisibleTopNavItems returns only visible top navigation items sorted by order
func (h *AuthHandler) getVisibleTopNavItems() []config.TopNavItem {
	var visibleItems []config.TopNavItem
	for _, item := range h.cfg.TopNavigation.Items {
		if item.Visible {
			visibleItems = append(visibleItems, item)
		}
	}
	// Sort by order using Go's efficient sort
	sort.Slice(visibleItems, func(i, j int) bool {
		return visibleItems[i].Order < visibleItems[j].Order
	})
	return visibleItems
}

// getVisibleProfileNavItems returns only visible profile navigation items sorted by order
func (h *AuthHandler) getVisibleProfileNavItems() []config.ProfileNavItem {
	var visibleItems []config.ProfileNavItem
	for _, item := range h.cfg.ProfileNavigation.Items {
		if item.Visible {
			visibleItems = append(visibleItems, item)
		}
	}
	// Sort by order using Go's efficient sort
	sort.Slice(visibleItems, func(i, j int) bool {
		return visibleItems[i].Order < visibleItems[j].Order
	})
	return visibleItems
}

// HomePage renders the home page
func (h *AuthHandler) HomePage(c *gin.Context) {
	lang := c.GetString("lang")
	var user *model.User
	if u, exists := c.Get("user"); exists {
		user = u.(*model.User)
	}

	// Check if we should redirect logged-in users to profile page
	if user != nil && h.cfg.Site.RedirectHomeToProfile {
		c.Redirect(http.StatusFound, "/profile")
		return
	}

	c.HTML(http.StatusOK, "home.html", gin.H{
		"lang":      lang,
		"user":      user,
		"logged":    user != nil,
		"siteTitle": h.getSiteTitle(lang),
		"custom":    h.cfg.Custom,
		"darkMode":  h.cfg.Site.DarkMode,
		"topNavItems": h.getVisibleTopNavItems(),
	})
}

// RechargePage renders the recharge page
func (h *AuthHandler) RechargePage(c *gin.Context) {
	lang := c.GetString("lang")
	var user *model.User
	if u, exists := c.Get("user"); exists {
		user = u.(*model.User)
	}

	c.HTML(http.StatusOK, "recharge.html", gin.H{
		"lang":      lang,
		"user":      user,
		"logged":    user != nil,
		"siteTitle": h.getSiteTitle(lang),
		"custom":    h.cfg.Custom,
		"darkMode":  h.cfg.Site.DarkMode,
		"topNavItems": h.getVisibleTopNavItems(),
	})
}

// VIPPage renders the VIP membership page
func (h *AuthHandler) VIPPage(c *gin.Context) {
	lang := c.GetString("lang")
	var user *model.User
	if u, exists := c.Get("user"); exists {
		user = u.(*model.User)
	}

	c.HTML(http.StatusOK, "vip.html", gin.H{
		"lang":      lang,
		"user":      user,
		"logged":    user != nil,
		"siteTitle": h.getSiteTitle(lang),
		"custom":    h.cfg.Custom,
		"darkMode":  h.cfg.Site.DarkMode,
		"topNavItems": h.getVisibleTopNavItems(),
	})
}

// ProfilePage renders the user profile page
func (h *AuthHandler) ProfilePage(c *gin.Context) {
	lang := c.GetString("lang")
	var user *model.User
	if u, exists := c.Get("user"); exists {
		user = u.(*model.User)
	}

	c.HTML(http.StatusOK, "profile.html", gin.H{
		"lang":      lang,
		"user":      user,
		"logged":    user != nil,
		"siteTitle": h.getSiteTitle(lang),
		"custom":    h.cfg.Custom,
		"darkMode":  h.cfg.Site.DarkMode,
		"topNavItems": h.getVisibleTopNavItems(),
		"profileNavItems": h.getVisibleProfileNavItems(),
	})
}

// PurchaseVIPRequest represents VIP purchase request
type PurchaseVIPRequest struct {
	Level    int `json:"level" binding:"required" example:"1"`
	Duration int `json:"duration" example:"30"` // Optional: specific duration to purchase (for multiple specifications). If not provided, uses default price/duration.
}

// RenewVIPRequest represents VIP renewal request
type RenewVIPRequest struct {
	Level    int `json:"level" binding:"required" example:"1"`
	Duration int `json:"duration" example:"30"` // Duration to add in days (for multiple specifications). If not provided, uses default duration.
}

// RedeemGiftCardRequest represents gift card redemption request
type RedeemGiftCardRequest struct {
	Code    string `json:"code" binding:"required" example:"XXXX-XXXX-XXXX-XXXX"`
	Confirm bool   `json:"confirm" example:"false"` // Set to true to confirm redemption when VIP conflict exists
}

// PreviewGiftCardRequest represents gift card preview request
type PreviewGiftCardRequest struct {
	Code string `json:"code" binding:"required" example:"XXXX-XXXX-XXXX-XXXX"`
}

// PurchaseVIP allows users to purchase VIP using balance
// @Summary Purchase VIP with balance
// @Description Purchase VIP membership using account balance. Supports upgrade from lower VIP levels with discounted prices.
// @Tags user
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body PurchaseVIPRequest true "VIP purchase request"
// @Success 200 {object} handler.Response "VIP purchased"
// @Failure 400 {object} handler.Response "Bad request or insufficient balance"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/purchase-vip [post]
func (h *AuthHandler) PurchaseVIP(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	var input PurchaseVIPRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Find the VIP level in config
	var vipConfig *config.VIPLevelConfig
	for _, v := range h.cfg.VIPLevels {
		if v.Level == input.Level {
			vipConfig = &v
			break
		}
	}

	if vipConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "VIP等级不存在",
		})
		return
	}

	// Prevent downgrade: users cannot purchase a VIP level lower than or equal to their current level
	if input.Level <= currentUser.VIPLevel {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "您已是该等级或更高等级的VIP，无法购买更低等级",
			"data": gin.H{
				"current_level":   currentUser.VIPLevel,
				"requested_level": input.Level,
			},
		})
		return
	}

	// Determine the actual price and duration based on specifications or default
	actualPrice := vipConfig.Price
	actualDuration := vipConfig.Duration
	var selectedSpec *config.VIPSpecification
	isUpgrade := currentUser.VIPLevel > 0

	// If duration is specified and specifications exist, find the matching specification
	if input.Duration > 0 && len(vipConfig.Specifications) > 0 {
		for i, spec := range vipConfig.Specifications {
			if spec.Duration == input.Duration {
				selectedSpec = &vipConfig.Specifications[i]
				actualPrice = spec.Price
				actualDuration = spec.Duration
				break
			}
		}
		// If duration specified but no matching specification found, use default
		if selectedSpec == nil {
			// Use default price/duration
			actualPrice = vipConfig.Price
			actualDuration = vipConfig.Duration
		}
	} else if input.Duration == 0 && len(vipConfig.Specifications) > 0 {
		// No duration specified but specifications exist - try to find matching default duration
		for i, spec := range vipConfig.Specifications {
			if spec.Duration == vipConfig.Duration {
				selectedSpec = &vipConfig.Specifications[i]
				actualPrice = spec.Price
				actualDuration = spec.Duration
				break
			}
		}
		// If no matching default found in specifications, use the config default
	}
	
	// Get old VIP config for prorated upgrade price calculation
	var oldVIPConfig *config.VIPLevelConfig
	if isUpgrade {
		for _, v := range h.cfg.VIPLevels {
			if v.Level == currentUser.VIPLevel {
				oldVIPConfig = &v
				break
			}
		}
	}

	// Calculate prorated upgrade price based on remaining days and upgrade coefficient
	if isUpgrade && vipConfig.UpgradeCoefficient > 0 && oldVIPConfig != nil {
		// Calculate remaining days from current VIP
		remainingDays := 0.0
		if currentUser.VIPExpireAt != nil && currentUser.VIPExpireAt.After(time.Now()) {
			remainingDuration := currentUser.VIPExpireAt.Sub(time.Now())
			remainingDays = remainingDuration.Hours() / 24
		}
		
		// Calculate old VIP's daily price
		oldDuration := float64(oldVIPConfig.Duration)
		if oldDuration <= 0 {
			oldDuration = 30 // Default to 30 days if not set
		}
		oldDailyPrice := oldVIPConfig.Price / oldDuration
		
		// Prorated upgrade price = new price - (remaining days * old daily price * coefficient)
		credit := remainingDays * oldDailyPrice * vipConfig.UpgradeCoefficient
		actualPrice = actualPrice - credit
		if actualPrice < 0 {
			actualPrice = 0
		}
		// Round to 2 decimal places
		actualPrice = float64(int(actualPrice*100+0.5)) / 100
	}

	// Check if user has enough balance
	if currentUser.Balance < actualPrice {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "余额不足，请先充值",
			"data": gin.H{
				"balance":    currentUser.Balance,
				"required":   actualPrice,
				"is_upgrade": isUpgrade,
			},
		})
		return
	}

	if h.userRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	// Store balance before deduction for logging
	balanceBefore := currentUser.Balance

	// Deduct balance (use actual price which may be prorated upgrade price)
	updatedUser, err := h.userRepo.UpdateBalance(currentUser.ID, -actualPrice)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "扣款失败",
		})
		return
	}

	// Set VIP level
	// For upgrades, just change VIP level without modifying expiration time
	// For new purchases, set VIP level with duration
	if isUpgrade {
		// Upgrade: only change VIP level, keep existing expiration time
		updatedUser, err = h.userRepo.SetVIPLevel(currentUser.ID, vipConfig.Level)
	} else {
		// New purchase: set VIP level with duration
		updatedUser, err = h.userRepo.SetVIPLevelWithDuration(currentUser.ID, vipConfig.Level, actualDuration)
	}
	if err != nil {
		// Refund balance if VIP upgrade fails - log if refund fails
		if _, refundErr := h.userRepo.UpdateBalance(currentUser.ID, actualPrice); refundErr != nil {
			// Critical: Log refund failure for manual intervention
			// In production, this should trigger an alert
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "VIP升级失败且退款异常，请联系客服",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "VIP升级失败，已退款",
		})
		return
	}

	// Create balance log for VIP purchase
	if h.balanceLogRepo != nil {
		reason := "购买" + vipConfig.Name
		if isUpgrade {
			reason = "升级至" + vipConfig.Name
		}
		balanceLog := &model.BalanceLog{
			UserID:        currentUser.ID,
			Amount:        -actualPrice,
			BalanceBefore: balanceBefore,
			BalanceAfter:  updatedUser.Balance,
			Type:          "purchase_vip",
			Reason:        reason,
			OperatorType:  "user",
		}
		h.balanceLogRepo.Create(balanceLog)
	}

	responseMessage := "VIP购买成功"
	if isUpgrade {
		responseMessage = "VIP升级成功"
	}

	responseData := gin.H{
		"vip_level":     updatedUser.VIPLevel,
		"vip_name":      vipConfig.Name,
		"vip_expire_at": updatedUser.VIPExpireAt,
		"balance":       updatedUser.Balance,
		"is_upgrade":    isUpgrade,
		"price_paid":    actualPrice,
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": responseMessage,
		"data":    responseData,
	})
}

// RenewVIP allows users to renew/extend their VIP membership using balance
// @Summary Renew VIP with balance
// @Description Renew VIP membership using account balance. If the user has active VIP, the duration is added to the current expiration. Only works if allow_renewal is enabled for the VIP level.
// @Tags user
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body RenewVIPRequest true "VIP renewal request"
// @Success 200 {object} handler.Response "VIP renewed"
// @Failure 400 {object} handler.Response "Bad request, insufficient balance, or renewal not allowed"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/renew-vip [post]
func (h *AuthHandler) RenewVIP(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	var input RenewVIPRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Find the VIP level in config
	var vipConfig *config.VIPLevelConfig
	for _, v := range h.cfg.VIPLevels {
		if v.Level == input.Level {
			vipConfig = &v
			break
		}
	}

	if vipConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "VIP等级不存在",
		})
		return
	}

	// Check if renewal is allowed for this VIP level
	if !vipConfig.AllowRenewal {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "该VIP等级不支持续期",
		})
		return
	}

	// User must have the same VIP level to renew
	if currentUser.VIPLevel != input.Level {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "只能续期当前VIP等级",
			"data": gin.H{
				"current_level":   currentUser.VIPLevel,
				"requested_level": input.Level,
			},
		})
		return
	}

	// Determine the actual price and duration based on specifications or default
	actualPrice := vipConfig.Price
	actualDuration := vipConfig.Duration
	var selectedSpec *config.VIPSpecification

	// If duration is specified and specifications exist, find the matching specification
	if input.Duration > 0 && len(vipConfig.Specifications) > 0 {
		for i, spec := range vipConfig.Specifications {
			if spec.Duration == input.Duration {
				selectedSpec = &vipConfig.Specifications[i]
				actualPrice = spec.Price
				actualDuration = spec.Duration
				break
			}
		}
		// If duration specified but no matching specification found, use default
		if selectedSpec == nil {
			actualPrice = vipConfig.Price
			actualDuration = vipConfig.Duration
		}
	} else if input.Duration == 0 && len(vipConfig.Specifications) > 0 {
		// No duration specified but specifications exist - try to find matching default duration
		for i, spec := range vipConfig.Specifications {
			if spec.Duration == vipConfig.Duration {
				selectedSpec = &vipConfig.Specifications[i]
				actualPrice = spec.Price
				actualDuration = spec.Duration
				break
			}
		}
	}

	// Check if user has enough balance
	if currentUser.Balance < actualPrice {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "余额不足，请先充值",
			"data": gin.H{
				"balance":  currentUser.Balance,
				"required": actualPrice,
			},
		})
		return
	}

	if h.userRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	// Store balance before deduction for logging
	balanceBefore := currentUser.Balance

	// Deduct balance
	updatedUser, err := h.userRepo.UpdateBalance(currentUser.ID, -actualPrice)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "扣款失败",
		})
		return
	}

	// Renew VIP (adds to existing expiration)
	updatedUser, err = h.userRepo.RenewVIPLevel(currentUser.ID, input.Level, actualDuration)
	if err != nil {
		// Refund balance if VIP renewal fails
		if _, refundErr := h.userRepo.UpdateBalance(currentUser.ID, actualPrice); refundErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "VIP续期失败且退款异常，请联系客服",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "VIP续期失败，已退款",
		})
		return
	}

	// Create balance log for VIP renewal
	if h.balanceLogRepo != nil {
		balanceLog := &model.BalanceLog{
			UserID:        currentUser.ID,
			Amount:        -actualPrice,
			BalanceBefore: balanceBefore,
			BalanceAfter:  updatedUser.Balance,
			Type:          "renew_vip",
			Reason:        "续期" + vipConfig.Name,
			OperatorType:  "user",
		}
		h.balanceLogRepo.Create(balanceLog)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "VIP续期成功",
		"data": gin.H{
			"vip_level":     updatedUser.VIPLevel,
			"vip_name":      vipConfig.Name,
			"vip_expire_at": updatedUser.VIPExpireAt,
			"balance":       updatedUser.Balance,
			"price_paid":    actualPrice,
			"duration_days": actualDuration,
		},
	})
}

// RedeemGiftCard allows users to redeem a gift card for balance or VIP membership
// @Summary Redeem gift card
// @Description Redeem a gift card to add balance and/or VIP membership to account. If the gift card contains VIP and the user already has an active VIP, confirmation is required.
// @Tags user
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body RedeemGiftCardRequest true "Gift card redemption request"
// @Success 200 {object} handler.Response "Gift card redeemed"
// @Failure 400 {object} handler.Response "Bad request or invalid code"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 409 {object} handler.Response "VIP conflict - requires confirmation"
// @Router /auth/redeem-gift-card [post]
func (h *AuthHandler) RedeemGiftCard(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	var input RedeemGiftCardRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if h.giftCardRepo == nil || h.userRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	// First, preview the gift card to check for VIP conflict
	previewCard, err := h.giftCardRepo.FindByCode(input.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "礼品卡无效或已被使用",
		})
		return
	}

	// Check if gift card is already used
	if previewCard.IsUsed {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "礼品卡无效或已被使用",
		})
		return
	}

	// Check if gift card is expired
	if previewCard.ExpiresAt != nil && previewCard.ExpiresAt.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "礼品卡已过期",
		})
		return
	}

	// Check for VIP conflict: gift card has VIP and user already has active VIP
	hasVIPConflict := false
	if previewCard.VIPLevel > 0 && currentUser.VIPLevel > 0 {
		// Check if user's current VIP is still valid (not expired)
		if currentUser.VIPExpireAt == nil || currentUser.VIPExpireAt.After(time.Now()) {
			hasVIPConflict = true
		}
	}

	// If there's a VIP conflict and user hasn't confirmed, return warning
	if hasVIPConflict && !input.Confirm {
		c.JSON(http.StatusConflict, gin.H{
			"success":          false,
			"requires_confirm": true,
			"message":          "您当前已有有效的VIP会员，礼品卡中的VIP将不会生效",
			"data": gin.H{
				"card_amount":           previewCard.Amount,
				"card_vip_level":        previewCard.VIPLevel,
				"card_vip_days":         previewCard.VIPDays,
				"current_vip_level":     currentUser.VIPLevel,
				"current_vip_expire_at": currentUser.VIPExpireAt,
			},
		})
		return
	}

	// Redeem the gift card
	giftCard, err := h.giftCardRepo.Redeem(input.Code, currentUser.ID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "礼品卡无效或已被使用",
		})
		return
	}

	var updatedUser *model.User
	balanceBefore := currentUser.Balance
	vipSkipped := false

	// Add balance to user if amount > 0
	if giftCard.Amount > 0 {
		updatedUser, err = h.userRepo.UpdateBalance(currentUser.ID, giftCard.Amount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "充值余额失败",
			})
			return
		}

		// Create balance log for gift card redemption
		if h.balanceLogRepo != nil {
			relatedID := giftCard.ID
			balanceLog := &model.BalanceLog{
				UserID:        currentUser.ID,
				Amount:        giftCard.Amount,
				BalanceBefore: balanceBefore,
				BalanceAfter:  updatedUser.Balance,
				Type:          "gift_card",
				Reason:        "礼品卡充值",
				OperatorType:  "user",
				RelatedID:     &relatedID,
			}
			h.balanceLogRepo.Create(balanceLog)
		}
	}

	// Grant VIP level if VIPLevel > 0 with duration from gift card
	// BUT only if there's no VIP conflict (user's current VIP is not active)
	if giftCard.VIPLevel > 0 {
		if hasVIPConflict {
			// VIP conflict - skip VIP grant
			vipSkipped = true
		} else {
			updatedUser, err = h.userRepo.SetVIPLevelWithDuration(currentUser.ID, giftCard.VIPLevel, giftCard.VIPDays)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"success": false,
					"message": "设置VIP等级失败",
				})
				return
			}
		}
	}

	// If neither balance nor VIP was set, fetch user for response
	if updatedUser == nil {
		updatedUser, err = h.userRepo.FindByID(currentUser.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "获取用户信息失败",
			})
			return
		}
	}

	// Build response data
	responseData := gin.H{
		"amount":        giftCard.Amount,
		"balance":       updatedUser.Balance,
		"vip_level":     updatedUser.VIPLevel,
		"vip_expire_at": updatedUser.VIPExpireAt,
		"vip_skipped":   vipSkipped,
	}

	// Add VIP-related fields if VIP was granted (not skipped)
	if giftCard.VIPLevel > 0 && !vipSkipped {
		responseData["granted_vip_level"] = giftCard.VIPLevel
		responseData["granted_vip_days"] = giftCard.VIPDays
	}

	// Build response message
	message := "礼品卡兑换成功"
	if vipSkipped {
		message = "礼品卡兑换成功。由于您已有有效的VIP会员，礼品卡中的VIP未生效。"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": message,
		"data":    responseData,
	})
}

// PreviewGiftCard allows users to preview a gift card before redeeming
// @Summary Preview gift card
// @Description Preview a gift card to see its contents and check for VIP conflicts before redeeming
// @Tags user
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body PreviewGiftCardRequest true "Gift card preview request"
// @Success 200 {object} handler.Response "Gift card preview"
// @Failure 400 {object} handler.Response "Bad request or invalid code"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/preview-gift-card [post]
func (h *AuthHandler) PreviewGiftCard(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	var input PreviewGiftCardRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	if h.giftCardRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	// Find the gift card
	giftCard, err := h.giftCardRepo.FindByCode(input.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "礼品卡无效",
		})
		return
	}

	// Check if gift card is already used
	if giftCard.IsUsed {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "礼品卡已被使用",
		})
		return
	}

	// Check if gift card is expired
	if giftCard.ExpiresAt != nil && giftCard.ExpiresAt.Before(time.Now()) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "礼品卡已过期",
		})
		return
	}

	// Check for VIP conflict
	hasVIPConflict := false
	if giftCard.VIPLevel > 0 && currentUser.VIPLevel > 0 {
		// Check if user's current VIP is still valid (not expired)
		if currentUser.VIPExpireAt == nil || currentUser.VIPExpireAt.After(time.Now()) {
			hasVIPConflict = true
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"amount":                giftCard.Amount,
			"vip_level":             giftCard.VIPLevel,
			"vip_days":              giftCard.VIPDays,
			"expires_at":            giftCard.ExpiresAt,
			"description":           giftCard.Description,
			"has_vip_conflict":      hasVIPConflict,
			"current_vip_level":     currentUser.VIPLevel,
			"current_vip_expire_at": currentUser.VIPExpireAt,
		},
	})
}

// GetBalance gets the current user's balance and VIP info
// @Summary Get balance and VIP info
// @Description Get current user's balance and VIP level
// @Tags user
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Balance and VIP info retrieved"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/balance [get]
func (h *AuthHandler) GetBalance(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	// Get VIP name if applicable
	var vipName string
	for _, v := range h.cfg.VIPLevels {
		if v.Level == currentUser.VIPLevel {
			vipName = v.Name
			break
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"balance":       currentUser.Balance,
			"vip_level":     currentUser.VIPLevel,
			"vip_name":      vipName,
			"vip_expire_at": currentUser.VIPExpireAt,
		},
	})
}

// SignedCallbackRequest represents a request to generate a signed callback URL
type SignedCallbackRequest struct {
	CallbackURL string `json:"callback_url" binding:"required" example:"https://your-app.com/callback"`
}

// SignedCallbackResponse represents the response with signed callback URL
type SignedCallbackResponse struct {
	CallbackURL string `json:"callback_url" example:"https://your-app.com/callback?uid=123&...&signature=abc123"`
}

// VerifySignatureRequest represents a request to verify a signed callback
type VerifySignatureRequest struct {
	UID       string `json:"uid" binding:"required" example:"123"`
	VIPLevel  string `json:"vip_level" binding:"required" example:"2"`
	Balance   string `json:"balance" binding:"required" example:"100.00"`
	Timestamp string `json:"ts" binding:"required" example:"1703136000"`
	Signature string `json:"signature" binding:"required" example:"abc123def456"`
}

// VerifySignatureResponse represents the verification result
type VerifySignatureResponse struct {
	Valid    bool    `json:"valid" example:"true"`
	UID      uint    `json:"uid,omitempty" example:"123"`
	VIPLevel int     `json:"vip_level,omitempty" example:"2"`
	Balance  float64 `json:"balance,omitempty" example:"100.00"`
}

// GetSignedURLStatus returns whether signed URL feature is enabled
// @Summary Get signed URL status
// @Description Check if signed URL callback feature is enabled
// @Tags auth
// @Produce json
// @Success 200 {object} handler.Response "Signed URL status"
// @Router /auth/signed-url/status [get]
func (h *AuthHandler) GetSignedURLStatus(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled":        h.cfg.SignedURL.Enabled,
			"expire_seconds": h.cfg.SignedURL.ExpireSeconds,
		},
	})
}

// GenerateSignedCallback generates a signed callback URL with user information
// @Summary Generate signed callback URL
// @Description Generate a callback URL with HMAC-signed user data (UID, VIP level, balance, etc.)
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body handler.SignedCallbackRequest true "Callback URL request"
// @Success 200 {object} handler.Response{data=handler.SignedCallbackResponse} "Signed callback URL"
// @Failure 400 {object} handler.Response "Bad request or feature disabled"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/signed-callback [post]
func (h *AuthHandler) GenerateSignedCallback(c *gin.Context) {
	// Check if feature is enabled
	if !h.cfg.SignedURL.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "签名URL功能未启用",
		})
		return
	}

	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	var input SignedCallbackRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Build simplified signed user data (only uid, vip_level, balance, ts)
	userData := &utils.SimplifiedSignedData{
		UID:       currentUser.ID,
		VIPLevel:  currentUser.VIPLevel,
		Balance:   currentUser.Balance,
		Timestamp: time.Now().Unix(),
	}

	// Generate signed callback URL with simplified parameters
	callbackURL, err := utils.BuildSimplifiedSignedCallbackURL(input.CallbackURL, h.cfg.SignedURL.Secret, userData)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "生成签名URL失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "签名回调URL生成成功",
		"data": gin.H{
			"callback_url": callbackURL,
		},
	})
}

// VerifySignedCallback verifies the signature of callback data
// @Summary Verify signed callback
// @Description Verify the HMAC signature of user data received from callback
// @Tags auth
// @Accept json
// @Produce json
// @Param request body handler.VerifySignatureRequest true "Verification request"
// @Success 200 {object} handler.Response{data=handler.VerifySignatureResponse} "Verification result"
// @Failure 400 {object} handler.Response "Bad request or feature disabled"
// @Router /auth/verify-signature [post]
func (h *AuthHandler) VerifySignedCallback(c *gin.Context) {
	// Check if feature is enabled
	if !h.cfg.SignedURL.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "签名URL功能未启用",
		})
		return
	}

	// Parse query parameters for signature verification
	queryParams := c.Request.URL.Query()

	// Allow both query parameters and JSON body
	if len(queryParams) == 0 || queryParams.Get("signature") == "" {
		// Try JSON body
		var input VerifySignatureRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "请求参数错误",
			})
			return
		}
		// Convert to query params format (simplified - only uid, vip_level, balance, ts)
		queryParams.Set("uid", input.UID)
		queryParams.Set("vip_level", input.VIPLevel)
		queryParams.Set("balance", input.Balance)
		queryParams.Set("ts", input.Timestamp)
		queryParams.Set("signature", input.Signature)
	}

	// Parse and verify the simplified signed data
	maxAge := time.Duration(h.cfg.SignedURL.ExpireSeconds) * time.Second
	userData, err := utils.ParseSimplifiedSignedCallback(queryParams, h.cfg.SignedURL.Secret, maxAge)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"valid":   false,
				"message": err.Error(),
			},
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"valid":     true,
			"uid":       userData.UID,
			"vip_level": userData.VIPLevel,
			"balance":   userData.Balance,
		},
	})
}

// SetLanguageRequest represents language setting request
type SetLanguageRequest struct {
	Lang string `json:"lang" binding:"required" example:"zh"`
}

// SetLanguage sets the user's preferred language
// @Summary Set language preference
// @Description Set the user's preferred language (stored in cookie)
// @Tags i18n
// @Accept json
// @Produce json
// @Param request body SetLanguageRequest true "Language setting request"
// @Success 200 {object} handler.Response "Language set"
// @Failure 400 {object} handler.Response "Bad request"
// @Router /i18n/set-language [post]
func (h *AuthHandler) SetLanguage(c *gin.Context) {
	var input struct {
		Lang string `json:"lang"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Validate language
	supportedLangs := []string{"en", "zh"}
	isValid := false
	for _, lang := range supportedLangs {
		if input.Lang == lang {
			isValid = true
			break
		}
	}

	if !isValid {
		input.Lang = "en" // Default to English
	}

	// Set language cookie (1 year expiry)
	c.SetCookie("lang", input.Lang, 365*24*3600, "/", "", isSecureRequest(c), false)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "语言设置成功",
		"data": gin.H{
			"lang": input.Lang,
		},
	})
}

// GetLanguage returns the user's current language preference
// @Summary Get language preference
// @Description Get the user's current language preference
// @Tags i18n
// @Produce json
// @Success 200 {object} handler.Response "Current language"
// @Router /i18n/language [get]
func (h *AuthHandler) GetLanguage(c *gin.Context) {
	lang := c.GetString("lang")
	if lang == "" {
		lang = "en"
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"lang":            lang,
			"supported_langs": []string{"en", "zh"},
		},
	})
}

// GetThirdPartyBindingStatus returns the binding status of third-party accounts
// @Summary Get third-party binding status
// @Description Get the binding status of Google, Steam, and Discord accounts
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Binding status"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/third-party-status [get]
func (h *AuthHandler) GetThirdPartyBindingStatus(c *gin.Context) {
	userID := c.GetUint("userID")

	status, err := h.authService.GetThirdPartyBindingStatus(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    status,
	})
}

// UnbindGoogle unbinds Google account from the current user
// @Summary Unbind Google account
// @Description Unbind Google account from the current user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Unbind successful"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/unbind/google [post]
func (h *AuthHandler) UnbindGoogle(c *gin.Context) {
	userID := c.GetUint("userID")

	if err := h.authService.UnbindGoogle(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Google账号解绑成功",
	})
}

// UnbindSteam unbinds Steam account from the current user
// @Summary Unbind Steam account
// @Description Unbind Steam account from the current user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Unbind successful"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/unbind/steam [post]
func (h *AuthHandler) UnbindSteam(c *gin.Context) {
	userID := c.GetUint("userID")

	if err := h.authService.UnbindSteam(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Steam账号解绑成功",
	})
}

// UnbindDiscord unbinds Discord account from the current user
// @Summary Unbind Discord account
// @Description Unbind Discord account from the current user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} handler.Response "Unbind successful"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/unbind/discord [post]
func (h *AuthHandler) UnbindDiscord(c *gin.Context) {
	userID := c.GetUint("userID")

	if err := h.authService.UnbindDiscord(userID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Discord账号解绑成功",
	})
}

// --- Email Verification Handlers ---

// VerifyEmailPage renders the email verification page
func (h *AuthHandler) VerifyEmailPage(c *gin.Context) {
	lang := c.GetString("lang")
	var user *model.User
	if u, exists := c.Get("user"); exists {
		user = u.(*model.User)
	}

	c.HTML(http.StatusOK, "verify_email.html", gin.H{
		"lang":           lang,
		"user":           user,
		"captchaEnabled": h.cfg.Captcha.Enabled,
		"custom":         h.cfg.Custom,
		"darkMode":       h.cfg.Site.DarkMode,
	})
}

// SendVerificationEmailRequest represents send verification email request body
type SendVerificationEmailRequest struct {
	Email     string `json:"email" binding:"required,email" example:"user@example.com"`
	CaptchaID string `json:"captcha_id" example:"abc123"`
}

// SendVerificationEmail sends a verification email to the user
// @Summary Send verification email
// @Description Send a verification email to the authenticated user. Rate limited to 1 email per 60 seconds.
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body SendVerificationEmailRequest true "Send verification email request"
// @Success 200 {object} handler.Response "Email sent"
// @Failure 400 {object} handler.Response "Bad request"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Failure 429 {object} handler.Response "Rate limit exceeded"
// @Router /auth/send-verification-email [post]
func (h *AuthHandler) SendVerificationEmail(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	var input SendVerificationEmailRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Verify captcha if enabled
	if h.cfg.Captcha.Enabled {
		if input.CaptchaID == "" || !h.captchaService.IsVerified(input.CaptchaID) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "请先完成验证码验证",
			})
			return
		}
	}

	if h.emailVerificationRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	// Check rate limit (60 seconds)
	canSend, remainingSeconds, err := h.emailVerificationRepo.CanSendVerificationEmail(currentUser.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	if !canSend {
		c.JSON(http.StatusTooManyRequests, gin.H{
			"success":           false,
			"message":           "发送过于频繁，请稍后重试",
			"remaining_seconds": remainingSeconds,
		})
		return
	}

	// Check if email is being changed
	targetEmail := input.Email
	if targetEmail != currentUser.Email {
		// Check if new email is already in use
		if h.userRepo.ExistsByEmail(targetEmail) {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"message": "该邮箱已被其他账户使用",
			})
			return
		}
		// Update user's email (will set EmailVerified to false)
		_, err := h.userRepo.UpdateEmail(currentUser.ID, targetEmail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"message": "更新邮箱失败",
			})
			return
		}
	}

	// Create verification token
	verifyToken, err := h.emailVerificationRepo.Create(currentUser.ID, targetEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "创建验证令牌失败",
		})
		return
	}

	// Get base URL from config or request
	baseURL := utils.GetBaseURL(c, h.cfg.Site.BaseURL)

	// Send verification email
	if err := h.emailService.SendEmailVerificationEmail(targetEmail, verifyToken.Token, baseURL); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "发送邮件失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "验证邮件已发送，请检查您的邮箱",
	})
}

// VerifyEmailCodeRequest represents email verification code request body
type VerifyEmailCodeRequest struct {
	Code string `json:"code" binding:"required" example:"123456"`
}

// VerifyEmailCode verifies an email verification code
// @Summary Verify email code
// @Description Verify email using the 6-digit code received via email
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body VerifyEmailCodeRequest true "Verification code request"
// @Success 200 {object} handler.Response "Email verified"
// @Failure 400 {object} handler.Response "Bad request or invalid code"
// @Failure 401 {object} handler.Response "Unauthorized"
// @Router /auth/verify-email-code [post]
func (h *AuthHandler) VerifyEmailCode(c *gin.Context) {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"success": false,
			"message": "请先登录",
		})
		return
	}

	currentUser := user.(*model.User)

	var input VerifyEmailCodeRequest
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请输入验证码",
		})
		return
	}

	if h.emailVerificationRepo == nil || h.userRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	// Find verification code by user ID and code
	verifyToken, err := h.emailVerificationRepo.FindByUserIDAndCode(currentUser.ID, input.Code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "验证码无效或已过期",
		})
		return
	}

	// Check if email matches (in case user changed email after requesting verification)
	if currentUser.Email != verifyToken.Email {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "邮箱地址已变更，请重新发送验证邮件",
		})
		return
	}

	// Mark email as verified
	_, err = h.userRepo.SetEmailVerified(verifyToken.UserID, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "验证失败，请稍后重试",
		})
		return
	}

	// Mark token as used
	h.emailVerificationRepo.MarkUsed(verifyToken.ID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "邮箱验证成功",
	})
}

// VerifyEmailToken verifies an email verification token (legacy, kept for backward compatibility)
// @Summary Verify email token
// @Description Verify email using the token from the verification email
// @Tags auth
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} handler.Response "Email verified"
// @Failure 400 {object} handler.Response "Bad request or invalid token"
// @Router /auth/verify-email-token [get]
func (h *AuthHandler) VerifyEmailToken(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "验证令牌缺失",
		})
		return
	}

	if h.emailVerificationRepo == nil || h.userRepo == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "服务暂不可用",
		})
		return
	}

	// Find verification token
	verifyToken, err := h.emailVerificationRepo.FindByToken(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "验证码无效或已过期",
		})
		return
	}

	// Get user
	user, err := h.userRepo.FindByID(verifyToken.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "用户不存在",
		})
		return
	}

	// Check if email matches (in case user changed email after requesting verification)
	if user.Email != verifyToken.Email {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "邮箱地址已变更，请重新发送验证邮件",
		})
		return
	}

	// Mark email as verified
	_, err = h.userRepo.SetEmailVerified(verifyToken.UserID, true)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "验证失败，请稍后重试",
		})
		return
	}

	// Mark token as used
	h.emailVerificationRepo.MarkUsed(verifyToken.ID)

	// Redirect to profile page with success message
	c.Redirect(http.StatusFound, "/profile?email_verified=1")
}
