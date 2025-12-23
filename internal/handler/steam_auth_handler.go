package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/gin-gonic/gin"
)

// steamIDRegex is a pre-compiled regex for extracting Steam ID from claimed_id
var steamIDRegex = regexp.MustCompile(`https://steamcommunity\.com/openid/id/(\d+)`)

// Steam OpenID verification errors
var (
	errSteamInvalidOpenIDMode  = errors.New("invalid OpenID mode")
	errSteamValidationFailed   = errors.New("Steam OpenID validation failed")
	errSteamInvalidSteamID     = errors.New("invalid Steam ID in response")
)

// SteamAuthHandler handles Steam OpenID authentication
type SteamAuthHandler struct {
	authService *service.AuthService
	cfg         *config.Config
}

// NewSteamAuthHandler creates a new SteamAuthHandler
func NewSteamAuthHandler(authService *service.AuthService, cfg *config.Config) *SteamAuthHandler {
	return &SteamAuthHandler{
		authService: authService,
		cfg:         cfg,
	}
}

// SteamPlayerSummary represents player summary from Steam API
type SteamPlayerSummary struct {
	SteamID      string `json:"steamid"`
	PersonaName  string `json:"personaname"`
	ProfileURL   string `json:"profileurl"`
	Avatar       string `json:"avatar"`
	AvatarMedium string `json:"avatarmedium"`
	AvatarFull   string `json:"avatarfull"`
}

// SteamLogin initiates Steam OpenID login
// @Summary Steam OpenID login
// @Description Redirect to Steam OpenID login page
// @Tags auth
// @Success 307 "Redirect to Steam OpenID"
// @Failure 400 {object} Response "Steam login not enabled"
// @Router /auth/steam/login [get]
func (h *SteamAuthHandler) SteamLogin(c *gin.Context) {
	if !h.cfg.SteamOAuth.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Steam 登录未启用",
		})
		return
	}

	redirectURL := h.cfg.SteamOAuth.RedirectURL
	if redirectURL == "" {
		// Try to construct from request
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		redirectURL = scheme + "://" + c.Request.Host + "/api/auth/steam/callback"
	}

	// Extract realm (base URL) from redirect URL using url.Parse
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "配置错误：无效的回调URL",
		})
		return
	}
	realm := parsedURL.Scheme + "://" + parsedURL.Host

	// Steam OpenID 2.0 authentication URL
	params := url.Values{}
	params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	params.Add("openid.mode", "checkid_setup")
	params.Add("openid.return_to", redirectURL)
	params.Add("openid.realm", realm)
	params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")

	authURL := "https://steamcommunity.com/openid/login?" + params.Encode()
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// SteamCallback handles Steam OpenID callback
// @Summary Steam OpenID callback
// @Description Handle Steam OpenID callback after user authentication
// @Tags auth
// @Success 302 "Redirect to home page"
// @Failure 302 "Redirect to login page with error"
// @Failure 400 {object} Response "Steam login not enabled"
// @Router /auth/steam/callback [get]
func (h *SteamAuthHandler) SteamCallback(c *gin.Context) {
	if !h.cfg.SteamOAuth.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Steam 登录未启用",
		})
		return
	}

	// Check if this is a bind request (indicated by steam_bind_mode cookie)
	bindMode, _ := c.Cookie("steam_bind_mode")
	if bindMode == "true" {
		// Clear the bind mode cookie
		c.SetCookie("steam_bind_mode", "", -1, "/", "", isSecureRequest(c), true)
		h.handleBindCallback(c)
		return
	}

	// Verify Steam OpenID and get player summary
	steamID, playerSummary, err := h.verifySteamOpenID(c)
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error=steam_auth_failed")
		return
	}

	// Login or register with Steam
	response, err := h.authService.LoginWithSteam(steamID, playerSummary.PersonaName, playerSummary.AvatarFull)
	if err != nil {
		c.Redirect(http.StatusFound, "/auth/login?error="+err.Error())
		return
	}

	// Set cookie (secure flag based on request protocol)
	c.SetCookie("token", response.Token, h.cfg.JWT.ExpireHour*3600, "/", "", isSecureRequest(c), true)

	c.Redirect(http.StatusFound, "/profile")
}

// handleBindCallback handles Steam OpenID callback for account binding
// This is called when the steam_bind_mode cookie is set, indicating a bind flow
// that was redirected to the login callback URL due to shared redirect URL
func (h *SteamAuthHandler) handleBindCallback(c *gin.Context) {
	// Get user ID from JWT token in cookie (user must be logged in)
	tokenString, err := c.Cookie("token")
	if err != nil || tokenString == "" {
		c.Redirect(http.StatusFound, "/profile?error=bind_unauthorized")
		return
	}

	// Validate token and get user
	user, err := h.authService.ValidateToken(tokenString)
	if err != nil {
		c.Redirect(http.StatusFound, "/profile?error=bind_unauthorized")
		return
	}

	// Verify Steam OpenID and get player summary
	steamID, playerSummary, err := h.verifySteamOpenID(c)
	if err != nil {
		c.Redirect(http.StatusFound, "/profile?error=steam_bind_failed")
		return
	}

	// Bind Steam account to existing user
	if err := h.authService.BindSteam(user.ID, steamID, playerSummary.PersonaName, playerSummary.AvatarFull); err != nil {
		c.Redirect(http.StatusFound, "/profile?error="+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/profile?success=steam_bind_success")
}

// verifySteamOpenID verifies the Steam OpenID response and returns the Steam ID and player summary
func (h *SteamAuthHandler) verifySteamOpenID(c *gin.Context) (string, *SteamPlayerSummary, error) {
	// Verify the OpenID response
	openIDMode := c.Query("openid.mode")
	if openIDMode != "id_res" {
		return "", nil, errSteamInvalidOpenIDMode
	}

	// Validate the response with Steam
	params := url.Values{}
	for key, values := range c.Request.URL.Query() {
		for _, value := range values {
			params.Add(key, value)
		}
	}
	params.Set("openid.mode", "check_authentication")

	resp, err := http.PostForm("https://steamcommunity.com/openid/login", params)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	if !strings.Contains(string(body), "is_valid:true") {
		return "", nil, errSteamValidationFailed
	}

	// Extract Steam ID from openid.claimed_id
	claimedID := c.Query("openid.claimed_id")
	matches := steamIDRegex.FindStringSubmatch(claimedID)
	if len(matches) < 2 {
		return "", nil, errSteamInvalidSteamID
	}
	steamID := matches[1]

	// Get user info from Steam API
	playerSummary, err := h.getSteamPlayerSummary(steamID)
	if err != nil {
		return "", nil, err
	}

	return steamID, playerSummary, nil
}

// getSteamPlayerSummary fetches player summary from Steam API
func (h *SteamAuthHandler) getSteamPlayerSummary(steamID string) (*SteamPlayerSummary, error) {
	apiURL := "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/"
	params := url.Values{}
	params.Add("key", h.cfg.SteamOAuth.APIKey)
	params.Add("steamids", steamID)

	resp, err := http.Get(apiURL + "?" + params.Encode())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Response struct {
			Players []SteamPlayerSummary `json:"players"`
		} `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Response.Players) == 0 {
		return &SteamPlayerSummary{SteamID: steamID, PersonaName: "Steam User"}, nil
	}

	return &result.Response.Players[0], nil
}

// SteamBindLogin initiates Steam OpenID for binding to existing account
// @Summary Steam OpenID bind
// @Description Redirect to Steam OpenID for binding to existing account
// @Tags auth
// @Security BearerAuth
// @Success 307 "Redirect to Steam OpenID"
// @Failure 400 {object} Response "Steam bind not enabled"
// @Router /auth/steam/bind [get]
func (h *SteamAuthHandler) SteamBindLogin(c *gin.Context) {
	if !h.cfg.SteamOAuth.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Steam 登录未启用",
		})
		return
	}

	if !h.cfg.SteamOAuth.AllowBind {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Steam账号绑定功能已关闭",
		})
		return
	}

	// Set a cookie to indicate bind mode (will be checked in callback)
	c.SetCookie("steam_bind_mode", "true", 600, "/", "", isSecureRequest(c), true)

	// Use bind-specific redirect URL if configured, otherwise use login redirect URL
	redirectURL := h.cfg.SteamOAuth.BindRedirectURL
	if redirectURL == "" {
		redirectURL = h.cfg.SteamOAuth.RedirectURL
	}
	if redirectURL == "" {
		scheme := "http"
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		redirectURL = scheme + "://" + c.Request.Host + "/api/auth/steam/bind/callback"
	}

	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "配置错误：无效的回调URL",
		})
		return
	}
	realm := parsedURL.Scheme + "://" + parsedURL.Host

	params := url.Values{}
	params.Add("openid.ns", "http://specs.openid.net/auth/2.0")
	params.Add("openid.mode", "checkid_setup")
	params.Add("openid.return_to", redirectURL)
	params.Add("openid.realm", realm)
	params.Add("openid.identity", "http://specs.openid.net/auth/2.0/identifier_select")
	params.Add("openid.claimed_id", "http://specs.openid.net/auth/2.0/identifier_select")

	authURL := "https://steamcommunity.com/openid/login?" + params.Encode()
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// SteamBindCallback handles Steam OpenID callback for binding to existing account
// @Summary Steam OpenID bind callback
// @Description Handle Steam OpenID callback for binding to existing account
// @Tags auth
// @Success 302 "Redirect to profile page"
// @Failure 302 "Redirect to profile page with error"
// @Failure 400 {object} Response "Steam login not enabled"
// @Router /auth/steam/bind/callback [get]
func (h *SteamAuthHandler) SteamBindCallback(c *gin.Context) {
	if !h.cfg.SteamOAuth.Enabled {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Steam 登录未启用",
		})
		return
	}

	// Get user ID from context (set by auth middleware)
	userID := c.GetUint("userID")
	if userID == 0 {
		c.Redirect(http.StatusFound, "/profile?error=bind_unauthorized")
		return
	}

	// Verify Steam OpenID and get player summary
	steamID, playerSummary, err := h.verifySteamOpenID(c)
	if err != nil {
		c.Redirect(http.StatusFound, "/profile?error=steam_bind_failed")
		return
	}

	// Bind Steam account to existing user
	if err := h.authService.BindSteam(userID, steamID, playerSummary.PersonaName, playerSummary.AvatarFull); err != nil {
		c.Redirect(http.StatusFound, "/profile?error="+err.Error())
		return
	}

	c.Redirect(http.StatusFound, "/profile?success=steam_bind_success")
}
