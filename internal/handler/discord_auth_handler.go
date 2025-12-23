package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// DiscordAuthHandler handles Discord OAuth authentication
type DiscordAuthHandler struct {
	authService *service.AuthService
	cfg         *config.Config
	oauthConfig *oauth2.Config
}

// DiscordEndpoint is the OAuth2 endpoint for Discord
var DiscordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/api/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

// NewDiscordAuthHandler creates a new DiscordAuthHandler
func NewDiscordAuthHandler(authService *service.AuthService, cfg *config.Config) *DiscordAuthHandler {
	var oauthConfig *oauth2.Config
	if cfg.DiscordOAuth.Enabled {
		oauthConfig = &oauth2.Config{
			ClientID:     cfg.DiscordOAuth.ClientID,
			ClientSecret: cfg.DiscordOAuth.ClientSecret,
			RedirectURL:  cfg.DiscordOAuth.RedirectURL,
			Scopes:       []string{"identify", "email"},
			Endpoint:     DiscordEndpoint,
		}
	}

	return &DiscordAuthHandler{
		authService: authService,
		cfg:         cfg,
		oauthConfig: oauthConfig,
	}
}

// DiscordUserInfo represents user info from Discord
type DiscordUserInfo struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	GlobalName    string `json:"global_name"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
}

// DiscordLoginAPIRequest represents Discord login API request
type DiscordLoginAPIRequest struct {
	AccessToken string `json:"access_token" binding:"required" example:"discord-access-token-xyz"`
}

// generateState generates a cryptographically secure random state for OAuth CSRF protection
func generateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// DiscordLogin initiates Discord OAuth login
// @Summary Discord OAuth login
// @Description Redirect to Discord OAuth login page
// @Tags auth
// @Success 307 "Redirect to Discord OAuth"
// @Failure 400 {object} Response "Discord login not enabled"
// @Router /auth/discord/login [get]
func (h *DiscordAuthHandler) DiscordLogin(c *gin.Context) {
	if !h.cfg.DiscordOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Discord 登录未启用",
		})
		return
	}

	// Generate secure random state for CSRF protection
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "生成安全状态失败",
		})
		return
	}

	// Store state in cookie for verification in callback
	c.SetCookie("discord_oauth_state", state, 600, "/", "", isSecureRequest(c), true)

	url := h.oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// DiscordCallback handles Discord OAuth callback
// @Summary Discord OAuth callback
// @Description Handle Discord OAuth callback after user authentication
// @Tags auth
// @Param code query string true "OAuth authorization code"
// @Success 302 "Redirect to home page"
// @Failure 302 "Redirect to login page with error"
// @Failure 400 {object} Response "Discord login not enabled"
// @Router /auth/discord/callback [get]
func (h *DiscordAuthHandler) DiscordCallback(c *gin.Context) {
	if !h.cfg.DiscordOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Discord 登录未启用",
		})
		return
	}

	// Verify state parameter for CSRF protection
	state := c.Query("state")
	storedState, err := c.Cookie("discord_oauth_state")
	if err != nil || state == "" || state != storedState {
		c.Redirect(http.StatusFound, "/auth/login?error=discord_auth_failed")
		return
	}
	// Clear the state cookie
	c.SetCookie("discord_oauth_state", "", -1, "/", "", isSecureRequest(c), true)

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusFound, "/auth/login?error=discord_auth_failed")
		return
	}

	// Exchange code for token
	token, err := h.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error=discord_auth_failed")
		return
	}

	// Get user info from Discord API
	userInfo, err := h.getDiscordUserInfo(token.AccessToken)
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error=discord_auth_failed")
		return
	}

	// Build avatar URL
	avatarURL := ""
	if userInfo.Avatar != "" {
		avatarURL = "https://cdn.discordapp.com/avatars/" + userInfo.ID + "/" + userInfo.Avatar + ".png"
	}

	// Get display name (prefer global_name, fall back to username)
	displayName := userInfo.GlobalName
	if displayName == "" {
		displayName = userInfo.Username
	}

	// Login or register with Discord
	response, err := h.authService.LoginWithDiscord(userInfo.ID, userInfo.Email, displayName, avatarURL)
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error="+err.Error())
		return
	}

	// Set cookie (secure flag based on request protocol)
	c.SetCookie("token", response.Token, h.cfg.JWT.ExpireHour*3600, "/", "", isSecureRequest(c), true)

	c.Redirect(http.StatusFound, "/profile")
}

// DiscordLoginAPI handles Discord OAuth login via API (for frontend SDK integration)
// @Summary Discord OAuth API login
// @Description Login with Discord using access token from frontend SDK
// @Tags auth
// @Accept json
// @Produce json
// @Param request body DiscordLoginAPIRequest true "Discord login request"
// @Success 200 {object} Response{data=service.AuthResponse} "Login successful"
// @Failure 400 {object} Response "Bad request or invalid token"
// @Router /auth/discord/login [post]
func (h *DiscordAuthHandler) DiscordLoginAPI(c *gin.Context) {
	if !h.cfg.DiscordOAuth.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Discord 登录未启用",
		})
		return
	}

	var input struct {
		AccessToken string `json:"access_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "请求参数错误",
		})
		return
	}

	// Get user info from Discord API
	userInfo, err := h.getDiscordUserInfo(input.AccessToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "验证 Discord 令牌失败",
		})
		return
	}

	// Build avatar URL
	avatarURL := ""
	if userInfo.Avatar != "" {
		avatarURL = "https://cdn.discordapp.com/avatars/" + userInfo.ID + "/" + userInfo.Avatar + ".png"
	}

	// Get display name (prefer global_name, fall back to username)
	displayName := userInfo.GlobalName
	if displayName == "" {
		displayName = userInfo.Username
	}

	// Login or register with Discord
	response, err := h.authService.LoginWithDiscord(userInfo.ID, userInfo.Email, displayName, avatarURL)
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

// getDiscordUserInfo fetches user info from Discord API
func (h *DiscordAuthHandler) getDiscordUserInfo(accessToken string) (*DiscordUserInfo, error) {
	req, err := http.NewRequest("GET", "https://discord.com/api/v10/users/@me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var userInfo DiscordUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// DiscordBindLogin initiates Discord OAuth for binding to existing account
// @Summary Discord OAuth bind
// @Description Redirect to Discord OAuth for binding to existing account
// @Tags auth
// @Security BearerAuth
// @Success 307 "Redirect to Discord OAuth"
// @Failure 400 {object} Response "Discord bind not enabled"
// @Router /auth/discord/bind [get]
func (h *DiscordAuthHandler) DiscordBindLogin(c *gin.Context) {
	if !h.cfg.DiscordOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Discord 登录未启用",
		})
		return
	}

	if !h.cfg.DiscordOAuth.AllowBind {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Discord账号绑定功能已关闭",
		})
		return
	}

	// Generate secure random state for CSRF protection
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "生成安全状态失败",
		})
		return
	}

	// Store state in cookie for verification in callback (with "bind_" prefix to indicate bind flow)
	c.SetCookie("discord_oauth_state", "bind_"+state, 600, "/", "", isSecureRequest(c), true)

	// Use bind-specific redirect URL if configured, otherwise use login redirect URL
	bindRedirectURL := h.cfg.DiscordOAuth.BindRedirectURL
	if bindRedirectURL == "" {
		bindRedirectURL = h.cfg.DiscordOAuth.RedirectURL
	}

	bindOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.DiscordOAuth.ClientID,
		ClientSecret: h.cfg.DiscordOAuth.ClientSecret,
		RedirectURL:  bindRedirectURL,
		Scopes:       []string{"identify", "email"},
		Endpoint:     DiscordEndpoint,
	}

	url := bindOauthConfig.AuthCodeURL("bind_"+state, oauth2.AccessTypeOnline)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// DiscordBindCallback handles Discord OAuth callback for binding to existing account
// @Summary Discord OAuth bind callback
// @Description Handle Discord OAuth callback for binding to existing account
// @Tags auth
// @Param code query string true "OAuth authorization code"
// @Success 302 "Redirect to profile page"
// @Failure 302 "Redirect to profile page with error"
// @Failure 400 {object} Response "Discord login not enabled"
// @Router /auth/discord/bind/callback [get]
func (h *DiscordAuthHandler) DiscordBindCallback(c *gin.Context) {
	if !h.cfg.DiscordOAuth.Enabled || h.oauthConfig == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Discord 登录未启用",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := c.GetUint("userID")
	if userID == 0 {
		c.Redirect(http.StatusFound, "/profile?error=bind_unauthorized")
		return
	}

	// Verify state parameter for CSRF protection
	state := c.Query("state")
	storedState, err := c.Cookie("discord_oauth_state")
	if err != nil || state == "" || state != storedState {
		c.Redirect(http.StatusFound, "/profile?error=discord_bind_failed")
		return
	}
	// Clear the state cookie
	c.SetCookie("discord_oauth_state", "", -1, "/", "", isSecureRequest(c), true)

	code := c.Query("code")
	if code == "" {
		c.Redirect(http.StatusFound, "/profile?error=discord_bind_failed")
		return
	}

	// Use bind-specific redirect URL if configured, otherwise use login redirect URL
	bindRedirectURL := h.cfg.DiscordOAuth.BindRedirectURL
	if bindRedirectURL == "" {
		bindRedirectURL = h.cfg.DiscordOAuth.RedirectURL
	}

	bindOauthConfig := &oauth2.Config{
		ClientID:     h.cfg.DiscordOAuth.ClientID,
		ClientSecret: h.cfg.DiscordOAuth.ClientSecret,
		RedirectURL:  bindRedirectURL,
		Scopes:       []string{"identify", "email"},
		Endpoint:     DiscordEndpoint,
	}

	// Exchange code for token
	token, err := bindOauthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.Redirect(http.StatusFound, "/profile?error=discord_bind_failed")
		return
	}

	// Get user info from Discord API
	userInfo, err := h.getDiscordUserInfo(token.AccessToken)
	if err != nil {
		c.Redirect(http.StatusFound, "/profile?error=discord_bind_failed")
		return
	}

	// Build avatar URL
	avatarURL := ""
	if userInfo.Avatar != "" {
		avatarURL = "https://cdn.discordapp.com/avatars/" + userInfo.ID + "/" + userInfo.Avatar + ".png"
	}

	// Get display name (prefer global_name, fall back to username)
	displayName := userInfo.GlobalName
	if displayName == "" {
		displayName = userInfo.Username
	}

	// Bind Discord account to existing user
	if err := h.authService.BindDiscord(userID, userInfo.ID, userInfo.Email, displayName, avatarURL); err != nil {
		c.Redirect(http.StatusFound, "/profile?error="+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/profile?success=discord_bind_success")
}
