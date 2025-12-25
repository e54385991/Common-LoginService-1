package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/e54385991/Common-LoginService/pkg/utils"
	"github.com/gin-gonic/gin"
)

// OAuth2Handler handles OAuth2 authorization server endpoints
type OAuth2Handler struct {
	authService  *service.AuthService
	cfg          *config.Config
	apiTokenRepo interface {
		FindByToken(token string) (*model.APIToken, error)
		UpdateLastUsed(id uint) error
	}
	// In-memory storage for authorization codes.
	// Note: For production use with multiple server instances, consider using Redis
	// or another shared storage solution. This in-memory implementation is suitable
	// for single-instance deployments and development/demo purposes.
	authCodes     map[string]*AuthorizationCode
	authCodeMutex sync.RWMutex
}

// AuthorizationCode represents an OAuth2 authorization code
type AuthorizationCode struct {
	Code        string
	ClientID    string
	UserID      uint
	Username    string
	VIPLevel    int
	RedirectURI string
	Scope       string
	ExpiresAt   time.Time
	Used        bool
	UsedAt      time.Time // Track when the code was marked as used
}

// NewOAuth2Handler creates a new OAuth2Handler
func NewOAuth2Handler(authService *service.AuthService, cfg *config.Config) *OAuth2Handler {
	h := &OAuth2Handler{
		authService: authService,
		cfg:         cfg,
		authCodes:   make(map[string]*AuthorizationCode),
	}
	// Start background cleanup goroutine
	go h.startCleanupRoutine()
	return h
}

// SetAPITokenRepo sets the API token repository
func (h *OAuth2Handler) SetAPITokenRepo(apiTokenRepo interface {
	FindByToken(token string) (*model.APIToken, error)
	UpdateLastUsed(id uint) error
}) {
	h.apiTokenRepo = apiTokenRepo
}

// generateAuthCode generates a random authorization code
func generateAuthCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Authorize handles the OAuth2 authorization endpoint
// GET /oauth2/authorize?response_type=code&client_id=xxx&redirect_uri=xxx&scope=xxx&state=xxx
func (h *OAuth2Handler) Authorize(c *gin.Context) {
	responseType := c.Query("response_type")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")

	// Validate response_type
	if responseType != "code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "Only 'code' response type is supported",
		})
		return
	}

	// Validate client_id (API Token)
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	// Validate redirect_uri
	if redirectURI == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "redirect_uri is required",
		})
		return
	}

	// Parse and validate redirect_uri
	parsedURI, err := url.Parse(redirectURI)
	if err != nil || (parsedURI.Scheme != "http" && parsedURI.Scheme != "https") || parsedURI.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid redirect_uri",
		})
		return
	}

	// Verify client_id exists (API Token check)
	if h.apiTokenRepo != nil {
		apiToken, err := h.apiTokenRepo.FindByToken(clientID)
		if err != nil || apiToken == nil || !apiToken.IsActive {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "Invalid client_id",
			})
			return
		}
	}

	// Check if user is already logged in
	if token, _ := c.Cookie("token"); token != "" {
		if user, err := h.authService.ValidateToken(token); err == nil {
			// User is logged in, generate authorization code
			code, err := generateAuthCode()
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":             "server_error",
					"error_description": "Failed to generate authorization code",
				})
				return
			}

			// Store authorization code
			h.authCodeMutex.Lock()
			h.authCodes[code] = &AuthorizationCode{
				Code:        code,
				ClientID:    clientID,
				UserID:      user.ID,
				Username:    user.Username,
				VIPLevel:    user.VIPLevel,
				RedirectURI: redirectURI,
				Scope:       scope,
				ExpiresAt:   time.Now().Add(10 * time.Minute),
				Used:        false,
			}
			h.authCodeMutex.Unlock()

			// Build redirect URL with code
			redirectURL := redirectURI
			if strings.Contains(redirectURL, "?") {
				redirectURL += "&"
			} else {
				redirectURL += "?"
			}
			redirectURL += "code=" + url.QueryEscape(code)
			if state != "" {
				redirectURL += "&state=" + url.QueryEscape(state)
			}

			c.Redirect(http.StatusFound, redirectURL)
			return
		}
	}

	// User not logged in, redirect to login page with oauth2 callback
	// Build a callback URL that will return to this authorize endpoint
	callbackURL := fmt.Sprintf("/oauth2/authorize?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		url.QueryEscape(responseType),
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(scope),
		url.QueryEscape(state),
	)
	loginURL := "/auth/login?callback=" + url.QueryEscape(callbackURL)
	c.Redirect(http.StatusFound, loginURL)
}

// TokenRequest represents the token exchange request
type TokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type"`
	Code         string `form:"code" json:"code"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
}

// TokenResponse represents the token exchange response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles the OAuth2 token endpoint
// POST /oauth2/token
func (h *OAuth2Handler) Token(c *gin.Context) {
	var req TokenRequest

	// Support both form and JSON
	contentType := c.GetHeader("Content-Type")
	if strings.Contains(contentType, "application/json") {
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Invalid request body",
			})
			return
		}
	} else {
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "Invalid request body",
			})
			return
		}
	}

	// Validate grant_type
	if req.GrantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only 'authorization_code' grant type is supported",
		})
		return
	}

	// Validate required fields
	if req.Code == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "code is required",
		})
		return
	}

	if req.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	// Verify client credentials (client_id = API Token)
	if h.apiTokenRepo != nil {
		apiToken, err := h.apiTokenRepo.FindByToken(req.ClientID)
		if err != nil || apiToken == nil || !apiToken.IsActive {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": "Invalid client credentials",
			})
			return
		}
		// Update last used time
		h.apiTokenRepo.UpdateLastUsed(apiToken.ID)
	}

	// Lookup authorization code
	h.authCodeMutex.RLock()
	authCode, exists := h.authCodes[req.Code]
	h.authCodeMutex.RUnlock()

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
		return
	}

	// Validate authorization code
	if authCode.Used {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Authorization code has already been used",
		})
		return
	}

	if time.Now().After(authCode.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Authorization code has expired",
		})
		return
	}

	if authCode.ClientID != req.ClientID {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "Client ID mismatch",
		})
		return
	}

	// Validate redirect_uri if provided
	if req.RedirectURI != "" && req.RedirectURI != authCode.RedirectURI {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": "redirect_uri mismatch",
		})
		return
	}

	// Mark code as used
	h.authCodeMutex.Lock()
	authCode.Used = true
	authCode.UsedAt = time.Now()
	h.authCodeMutex.Unlock()

	// Generate access token (simplified - using a signed token)
	accessToken, err := h.generateAccessToken(authCode.UserID, authCode.Username, authCode.VIPLevel, authCode.Scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate access token",
		})
		return
	}

	// Return token response
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // 1 hour
		Scope:       authCode.Scope,
	})
}

// OAuth2AccessToken represents the claims in an OAuth2 access token
type OAuth2AccessToken struct {
	UserID    uint   `json:"user_id"`
	Username  string `json:"username"`
	VIPLevel  int    `json:"vip_level"`
	Scope     string `json:"scope"`
	ExpiresAt int64  `json:"exp"`
}

// generateAccessToken generates a signed access token
func (h *OAuth2Handler) generateAccessToken(userID uint, username string, vipLevel int, scope string) (string, error) {
	token := OAuth2AccessToken{
		UserID:    userID,
		Username:  username,
		VIPLevel:  vipLevel,
		Scope:     scope,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	// Encode token as JSON
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return "", err
	}

	// Create signature using HMAC
	signature := utils.ComputeHMAC(string(tokenJSON), h.cfg.JWT.Secret)

	// Combine token and signature
	tokenStr := base64.URLEncoding.EncodeToString(tokenJSON) + "." + signature

	return tokenStr, nil
}

// parseAccessToken parses and validates an access token
func (h *OAuth2Handler) parseAccessToken(tokenStr string) (*OAuth2AccessToken, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	tokenJSON, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding")
	}

	// Verify signature
	expectedSig := utils.ComputeHMAC(string(tokenJSON), h.cfg.JWT.Secret)
	if parts[1] != expectedSig {
		return nil, fmt.Errorf("invalid token signature")
	}

	var token OAuth2AccessToken
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		return nil, fmt.Errorf("invalid token payload")
	}

	// Check expiration
	if time.Now().Unix() > token.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &token, nil
}

// UserInfo handles the OAuth2 userinfo endpoint
// GET /oauth2/userinfo
func (h *OAuth2Handler) UserInfo(c *gin.Context) {
	// Get access token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Missing access token",
		})
		return
	}

	// Parse Bearer token
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "Invalid Authorization header format",
		})
		return
	}

	accessToken := parts[1]

	// Parse and validate access token
	token, err := h.parseAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": err.Error(),
		})
		return
	}

	// Return user info
	c.JSON(http.StatusOK, gin.H{
		"sub":       fmt.Sprintf("%d", token.UserID),
		"user_id":   token.UserID,
		"username":  token.Username,
		"vip_level": token.VIPLevel,
	})
}

// startCleanupRoutine starts a background goroutine for periodic cleanup of expired authorization codes
func (h *OAuth2Handler) startCleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		h.cleanupExpiredCodes()
	}
}

// cleanupExpiredCodes removes expired authorization codes
func (h *OAuth2Handler) cleanupExpiredCodes() {
	h.authCodeMutex.Lock()
	defer h.authCodeMutex.Unlock()

	now := time.Now()
	for code, authCode := range h.authCodes {
		// Remove codes that are:
		// 1. Expired (past their ExpiresAt time)
		// 2. Used and have been used for more than 1 hour (to allow for any in-flight requests)
		if now.After(authCode.ExpiresAt) {
			delete(h.authCodes, code)
		} else if authCode.Used && !authCode.UsedAt.IsZero() && now.Sub(authCode.UsedAt) > time.Hour {
			delete(h.authCodes, code)
		}
	}
}

// GetOAuth2Status returns OAuth2 server status
// @Summary Get OAuth2 status
// @Description Check if OAuth2 server is enabled
// @Tags oauth2
// @Produce json
// @Success 200 {object} Response "OAuth2 status"
// @Router /oauth2/status [get]
func (h *OAuth2Handler) GetOAuth2Status(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"enabled": true, // OAuth2 is always available when the server is running
		},
	})
}
