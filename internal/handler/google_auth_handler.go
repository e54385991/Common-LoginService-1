package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleAuthHandler handles Google OAuth authentication
type GoogleAuthHandler struct {
	authService *service.AuthService
	cfg         *config.Config
	oauthConfig *oauth2.Config
}

// NewGoogleAuthHandler creates a new GoogleAuthHandler
func NewGoogleAuthHandler(authService *service.AuthService, cfg *config.Config) *GoogleAuthHandler {
	var oauthConfig *oauth2.Config
	if cfg.GoogleOAuth.Enabled {
		oauthConfig = &oauth2.Config{
			ClientID:     cfg.GoogleOAuth.ClientID,
			ClientSecret: cfg.GoogleOAuth.ClientSecret,
			RedirectURL:  cfg.GoogleOAuth.RedirectURL,
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		}
	}

	return &GoogleAuthHandler{
		authService: authService,
		cfg:         cfg,
		oauthConfig: oauthConfig,
	}
}

// GoogleUserInfo represents user info from Google
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// GoogleLoginAPIRequest represents Google login API request
type GoogleLoginAPIRequest struct {
	IDToken string `json:"id_token" binding:"required" example:"google-id-token-xyz"`
}

// GoogleLogin initiates Google OAuth login
// @Summary Google OAuth login
// @Description Redirect to Google OAuth login page
// @Tags auth
// @Success 307 "Redirect to Google OAuth"
// @Failure 400 {object} Response "Google login not enabled"
// @Router /auth/google/login [get]
func (h *GoogleAuthHandler) GoogleLogin(c *gin.Context) {
	if !h.cfg.GoogleOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Google 登录未启用",
		})
		return
	}

	url := h.oauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GoogleCallback handles Google OAuth callback
// @Summary Google OAuth callback
// @Description Handle Google OAuth callback after user authentication
// @Tags auth
// @Param code query string true "OAuth authorization code"
// @Success 302 "Redirect to home page"
// @Failure 302 "Redirect to login page with error"
// @Failure 400 {object} Response "Google login not enabled"
// @Router /auth/google/callback [get]
func (h *GoogleAuthHandler) GoogleCallback(c *gin.Context) {
	if !h.cfg.GoogleOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Google 登录未启用",
		})
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusFound, "/auth/login?error=google_auth_failed")
		return
	}

	// Exchange code for token
	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error=google_auth_failed")
		return
	}

	// Get user info
	client := h.oauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error=google_auth_failed")
		return
	}
	defer resp.Body.Close()

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error=google_auth_failed")
		return
	}

	// Login or register with Google
	response, err := h.authService.LoginWithGoogle(userInfo.ID, userInfo.Email, userInfo.Name, userInfo.Picture)
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error="+err.Error())
		return
	}

	// Set cookie (secure flag based on request protocol)
	c.SetCookie("token", response.Token, h.cfg.JWT.ExpireHour*3600, "/", "", isSecureRequest(c), true)

	c.Redirect(http.StatusFound, "/profile")
}

// GoogleLoginAPI handles Google OAuth login via API (for frontend SDK integration)
// @Summary Google OAuth API login
// @Description Login with Google using ID token from frontend SDK
// @Tags auth
// @Accept json
// @Produce json
// @Param request body GoogleLoginAPIRequest true "Google login request"
// @Success 200 {object} Response{data=service.AuthResponse} "Login successful"
// @Failure 400 {object} Response "Bad request or invalid token"
// @Router /auth/google/login [post]
func (h *GoogleAuthHandler) GoogleLoginAPI(c *gin.Context) {
	if !h.cfg.GoogleOAuth.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Google 登录未启用",
		})
		return
	}

	var input struct {
		IDToken string `json:"id_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Verify the ID token with Google
	// In production, you should verify the token properly
	// For now, we'll use the Google API to get user info
	resp, err := http.Get("https://oauth2.googleapis.com/tokeninfo?id_token=" + input.IDToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "验证 Google 令牌失败",
		})
		return
	}
	defer resp.Body.Close()

	var tokenInfo struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified string `json:"email_verified"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		Aud           string `json:"aud"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "解析 Google 令牌失败",
		})
		return
	}

	// Verify the audience matches our client ID
	if tokenInfo.Aud != h.cfg.GoogleOAuth.ClientID {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "无效的 Google 令牌",
		})
		return
	}

	// Login or register with Google
	response, err := h.authService.LoginWithGoogle(tokenInfo.Sub, tokenInfo.Email, tokenInfo.Name, tokenInfo.Picture)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
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

// GoogleBindCallback handles Google OAuth callback for binding to existing account
// @Summary Google OAuth bind callback
// @Description Handle Google OAuth callback for binding to existing account
// @Tags auth
// @Param code query string true "OAuth authorization code"
// @Success 302 "Redirect to profile page"
// @Failure 302 "Redirect to profile page with error"
// @Failure 400 {object} Response "Google login not enabled"
// @Router /auth/google/bind/callback [get]
func (h *GoogleAuthHandler) GoogleBindCallback(c *gin.Context) {
	if !h.cfg.GoogleOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Google 登录未启用",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := c.GetUint("userID")
	if userID == 0 {
		c.Redirect(http.StatusFound, "/profile?error=bind_unauthorized")
		return
	}

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusFound, "/profile?error=google_bind_failed")
		return
	}

	// Use bind-specific redirect URL if configured, otherwise use login redirect URL
	bindRedirectURL := h.cfg.GoogleOAuth.BindRedirectURL
	if bindRedirectURL == "" {
		bindRedirectURL = h.cfg.GoogleOAuth.RedirectURL
	}

	// Create bind-specific OAuth config for token exchange
	bindOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.GoogleOAuth.ClientID,
		ClientSecret: h.cfg.GoogleOAuth.ClientSecret,
		RedirectURL:  bindRedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	// Exchange code for token
	token, err := bindOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.Redirect(http.StatusFound, "/profile?error=google_bind_failed")
		return
	}

	// Get user info
	client := bindOauthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		c.Redirect(http.StatusFound, "/profile?error=google_bind_failed")
		return
	}
	defer resp.Body.Close()

	var userInfo GoogleUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		c.Redirect(http.StatusFound, "/profile?error=google_bind_failed")
		return
	}

	// Bind Google account to existing user
	if err := h.authService.BindGoogle(userID, userInfo.ID, userInfo.Email, userInfo.Name, userInfo.Picture); err != nil {
		c.Redirect(http.StatusFound, "/profile?error="+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/profile?success=google_bind_success")
}

// GoogleBindLogin initiates Google OAuth for binding to existing account
// @Summary Google OAuth bind
// @Description Redirect to Google OAuth for binding to existing account
// @Tags auth
// @Security BearerAuth
// @Success 307 "Redirect to Google OAuth"
// @Failure 400 {object} Response "Google bind not enabled"
// @Router /auth/google/bind [get]
func (h *GoogleAuthHandler) GoogleBindLogin(c *gin.Context) {
	if !h.cfg.GoogleOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Google 登录未启用",
		})
		return
	}

	if !h.cfg.GoogleOAuth.AllowBind {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Google账号绑定功能已关闭",
		})
		return
	}

	// Use bind-specific redirect URL if configured, otherwise use login redirect URL
	bindRedirectURL := h.cfg.GoogleOAuth.BindRedirectURL
	if bindRedirectURL == "" {
		// Fall back to login redirect URL (same URL for both login and bind)
		bindRedirectURL = h.cfg.GoogleOAuth.RedirectURL
	}

	bindOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.GoogleOAuth.ClientID,
		ClientSecret: h.cfg.GoogleOAuth.ClientSecret,
		RedirectURL:  bindRedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	url := bindOauthConfig.AuthCodeURL("bind", oauth2.AccessTypeOffline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}
