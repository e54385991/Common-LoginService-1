package middleware

import (
	"net/http"
	"strings"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/i18n"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/repository"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/gin-gonic/gin"
)

// UserRepository interface for VIP expiration check
type UserRepository interface {
	CheckAndExpireVIP(user *model.User) (bool, error)
}

// userRepo holds the user repository reference for VIP expiration checks
var userRepo UserRepository

// SetUserRepository sets the user repository for middleware VIP expiration checks
func SetUserRepository(repo UserRepository) {
	userRepo = repo
}

// checkAndExpireVIP checks if user's VIP has expired and resets if necessary
func checkAndExpireVIP(user *model.User) {
	if userRepo == nil {
		return
	}
	
	// Delegate all VIP expiration logic to the repository
	userRepo.CheckAndExpireVIP(user)
}

// AuthMiddleware creates authentication middleware
func AuthMiddleware(authService *service.AuthService, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from header or cookie
		tokenString := ""

		// Try Authorization header first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				tokenString = parts[1]
			}
		}

		// Try cookie if header not found
		if tokenString == "" {
			tokenString, _ = c.Cookie("token")
		}

		lang := c.GetString("lang")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": i18n.T(lang, "error.invalid_token"),
			})
			c.Abort()
			return
		}

		user, err := authService.ValidateToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Check and auto-expire VIP if necessary
		checkAndExpireVIP(user)

		// Set user in context
		c.Set("user", user)
		c.Set("userID", user.ID)
		c.Next()
	}
}

// AdminMiddleware creates admin authentication middleware
func AdminMiddleware(authService *service.AuthService, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check if it's an admin session via cookie
		adminSession, _ := c.Cookie("admin_session")
		if adminSession == "true" {
			c.Next()
			return
		}

		// Check for JWT token
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

		if tokenString != "" {
			user, err := authService.ValidateToken(tokenString)
			if err == nil && user.IsAdmin {
				c.Set("user", user)
				c.Set("userID", user.ID)
				c.Next()
				return
			}
		}

		// Redirect to admin login for page requests
		if c.GetHeader("Accept") == "" || strings.Contains(c.GetHeader("Accept"), "text/html") {
			c.Redirect(http.StatusFound, "/admin/login")
			c.Abort()
			return
		}

		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"message": "Admin access required",
		})
		c.Abort()
	}
}

// OptionalAuthMiddleware creates optional authentication middleware
func OptionalAuthMiddleware(authService *service.AuthService, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
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

		if tokenString != "" {
			user, err := authService.ValidateToken(tokenString)
			if err == nil {
				// Check and auto-expire VIP if necessary
				checkAndExpireVIP(user)
				c.Set("user", user)
				c.Set("userID", user.ID)
			}
		}

		c.Next()
	}
}

// APITokenMiddleware creates API token authentication middleware
func APITokenMiddleware(apiTokenRepo *repository.APITokenRepository) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get token from header
		tokenString := ""
		
		// Try X-API-Key header first
		tokenString = c.GetHeader("X-API-Key")
		
		// Try Authorization header with Bearer scheme
		if tokenString == "" {
			authHeader := c.GetHeader("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
					tokenString = parts[1]
				}
			}
		}

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "API令牌缺失",
			})
			c.Abort()
			return
		}

		apiToken, err := apiTokenRepo.FindByToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"message": "无效的API令牌",
			})
			c.Abort()
			return
		}

		// Set API token in context
		c.Set("api_token", apiToken)
		c.Next()
	}
}

// CORSMiddleware creates CORS middleware
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, X-API-Key")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// I18nMiddleware detects user language from Accept-Language header
func I18nMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check for lang cookie first
		lang, err := c.Cookie("lang")
		if err != nil || lang == "" {
			// Parse Accept-Language header
			acceptLang := c.GetHeader("Accept-Language")
			lang = i18n.GetLangFromAcceptHeader(acceptLang)
		}

		// Set language in context
		c.Set("lang", lang)
		c.Next()
	}
}

// EmailVerificationMiddleware creates middleware to check email verification status
// If RequireEmailVerification is enabled and user's email is not verified,
// redirects to the email verification page (for page requests) or returns an error (for API requests)
func EmailVerificationMiddleware(authService *service.AuthService, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if email verification is not required
		if !cfg.Access.RequireEmailVerification {
			c.Next()
			return
		}

		// Get token from header or cookie
		tokenString := ""

		// Try Authorization header first
		authHeader := c.GetHeader("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				tokenString = parts[1]
			}
		}

		// Try cookie if header not found
		if tokenString == "" {
			tokenString, _ = c.Cookie("token")
		}

		// If no token, let other middleware handle it
		if tokenString == "" {
			c.Next()
			return
		}

		user, err := authService.ValidateToken(tokenString)
		if err != nil {
			// Let other middleware handle invalid tokens
			c.Next()
			return
		}

		// If email is already verified, continue
		if user.EmailVerified {
			c.Next()
			return
		}

		// Email not verified - check if this is a page request or API request
		acceptHeader := c.GetHeader("Accept")
		if acceptHeader == "" || strings.Contains(acceptHeader, "text/html") {
			// Page request - redirect to email verification page
			c.Redirect(http.StatusFound, "/auth/verify-email")
			c.Abort()
			return
		}

		// API request - return error
		c.JSON(http.StatusForbidden, gin.H{
			"success":            false,
			"message":            "请先验证您的邮箱地址",
			"require_email_verification": true,
		})
		c.Abort()
	}
}
