package main

import (
	"encoding/json"
	"html/template"
	"log"
	"os"
	"path/filepath"

	"github.com/e54385991/Common-LoginService/config"
	_ "github.com/e54385991/Common-LoginService/docs"
	"github.com/e54385991/Common-LoginService/internal/handler"
	"github.com/e54385991/Common-LoginService/internal/i18n"
	"github.com/e54385991/Common-LoginService/internal/middleware"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/repository"
	"github.com/e54385991/Common-LoginService/internal/service"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// @title Common Login Service API
// @version 1.0
// @description Common Login Service 提供用户认证、注册、登录等功能的 API 服务
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /api

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT token for authorization (format: Bearer {token})

// loadTemplates loads all HTML templates from the templates directory
func loadTemplates(templatesDir string) (*template.Template, error) {
	tmpl := template.New("")

	// Add i18n function and safe JavaScript escaping function to templates
	tmpl.Funcs(template.FuncMap{
		"t": func(lang, key string) string {
			return i18n.T(lang, key)
		},
		// js safely escapes a string for use in JavaScript string context.
		// It uses JSON encoding to handle special characters, then strips the
		// surrounding quotes since the template already provides them.
		"js": func(s string) template.JS {
			b, err := json.Marshal(s)
			if err != nil {
				return template.JS("")
			}
			// Strip surrounding quotes from JSON string
			if len(b) >= 2 {
				return template.JS(b[1 : len(b)-1])
			}
			return template.JS("")
		},
		// urlquery URL-encodes a string for use in URL query parameters
		"urlquery": func(s string) string {
			return template.URLQueryEscaper(s)
		},
	})

	err := filepath.Walk(templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Ext(path) != ".html" {
			return nil
		}

		// Get relative path from templates directory and use the filename as template name
		relPath, err := filepath.Rel(templatesDir, path)
		if err != nil {
			return err
		}

		// Use just the filename as template name for simplicity
		name := filepath.Base(relPath)
		
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		_, err = tmpl.New(name).Parse(string(content))
		return err
	})

	return tmpl, err
}

func main() {
	// Load configuration
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Printf("Warning: Could not load config file: %v, using defaults", err)
	}

	// Initialize i18n
	i18n.Init()

	// Initialize database (MySQL)
	dsn := cfg.Database.GetDSN()
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto migrate
	if err := db.AutoMigrate(&model.User{}, &model.Session{}, &model.SystemConfig{}, &model.PasswordResetRequest{}, &model.APIToken{}, &model.GiftCard{}, &model.PaymentOrder{}, &model.BalanceLog{}, &model.LoginLog{}, &model.EmailVerificationToken{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	configRepo := repository.NewConfigRepository(db)
	apiTokenRepo := repository.NewAPITokenRepository(db)
	giftCardRepo := repository.NewGiftCardRepository(db)
	paymentOrderRepo := repository.NewPaymentOrderRepository(db)
	balanceLogRepo := repository.NewBalanceLogRepository(db)
	loginLogRepo := repository.NewLoginLogRepository(db)
	emailVerificationRepo := repository.NewEmailVerificationRepository(db)

	// Initialize session store based on configuration
	var sessionStore repository.SessionStore
	if cfg.Session.StorageType == "redis" {
		redisStore, err := repository.NewRedisSessionStore(&cfg.Session.Redis)
		if err != nil {
			log.Fatalf("Failed to connect to Redis: %v", err)
		}
		sessionStore = redisStore
		log.Printf("Using Redis for session storage at %s:%s", cfg.Session.Redis.Host, cfg.Session.Redis.Port)
	} else {
		sessionStore = repository.NewSessionRepository(db)
		log.Printf("Using MySQL for session storage")
	}

	// Initialize services
	authService := service.NewAuthService(userRepo, sessionStore, cfg)
	authService.SetLoginLogRepo(loginLogRepo)
	emailService := service.NewEmailService(cfg)
	captchaService := service.NewCaptchaService()

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, emailService, captchaService, cfg)
	authHandler.SetUserRepo(userRepo)
	authHandler.SetGiftCardRepo(giftCardRepo)
	authHandler.SetBalanceLogRepo(balanceLogRepo)
	authHandler.SetEmailVerificationRepo(emailVerificationRepo)
	googleHandler := handler.NewGoogleAuthHandler(authService, cfg)
	steamHandler := handler.NewSteamAuthHandler(authService, cfg)
	discordHandler := handler.NewDiscordAuthHandler(authService, cfg)
	adminHandler := handler.NewAdminHandler(cfg, configRepo, userRepo, apiTokenRepo, giftCardRepo, balanceLogRepo, sessionStore)
	adminHandler.SetLoginLogRepo(loginLogRepo)
	captchaHandler := handler.NewCaptchaHandler(captchaService, cfg)
	paymentHandler := handler.NewPaymentHandler(cfg, paymentOrderRepo, userRepo, balanceLogRepo)

	// Initialize Gin
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Set user repository for middleware VIP expiration checks
	middleware.SetUserRepository(userRepo)

	// Load templates
	tmpl, err := loadTemplates("templates")
	if err != nil {
		log.Fatalf("Failed to load templates: %v", err)
	}
	r.SetHTMLTemplate(tmpl)

	// Static files
	r.Static("/static", "./static")

	// CORS middleware
	r.Use(middleware.CORSMiddleware())

	// i18n middleware
	r.Use(middleware.I18nMiddleware())

	// Public routes - Pages
	r.GET("/", middleware.OptionalAuthMiddleware(authService, cfg), authHandler.HomePage)
	r.GET("/auth/login", authHandler.LoginPage)
	r.GET("/auth/register", authHandler.RegisterPage)
	r.GET("/auth/forgot-password", authHandler.ForgotPasswordPage)
	r.GET("/auth/reset-password", authHandler.ResetPasswordPage)
	r.GET("/auth/verify-email", middleware.OptionalAuthMiddleware(authService, cfg), authHandler.VerifyEmailPage)
	r.GET("/recharge", middleware.OptionalAuthMiddleware(authService, cfg), middleware.EmailVerificationMiddleware(authService, cfg), authHandler.RechargePage)
	r.GET("/vip", middleware.OptionalAuthMiddleware(authService, cfg), middleware.EmailVerificationMiddleware(authService, cfg), authHandler.VIPPage)
	r.GET("/profile", middleware.OptionalAuthMiddleware(authService, cfg), middleware.EmailVerificationMiddleware(authService, cfg), authHandler.ProfilePage)

	// Public routes - API
	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/logout", authHandler.Logout)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)
			auth.POST("/validate", authHandler.ValidateToken)
			auth.GET("/google/status", authHandler.GetGoogleOAuthStatus)
			auth.GET("/google/login", googleHandler.GoogleLogin)
			auth.GET("/google/callback", googleHandler.GoogleCallback)
			auth.POST("/google/login", googleHandler.GoogleLoginAPI)
			// Steam OAuth routes
			auth.GET("/steam/login", steamHandler.SteamLogin)
			auth.GET("/steam/callback", steamHandler.SteamCallback)
			// Discord OAuth routes
			auth.GET("/discord/login", discordHandler.DiscordLogin)
			auth.GET("/discord/callback", discordHandler.DiscordCallback)
			auth.POST("/discord/login", discordHandler.DiscordLoginAPI)
			// Signed URL routes (public)
			auth.GET("/signed-url/status", authHandler.GetSignedURLStatus)
			auth.POST("/verify-signature", authHandler.VerifySignedCallback)
			// Email verification routes (public - token in query)
			auth.GET("/verify-email-token", authHandler.VerifyEmailToken)
		}

		// i18n routes (public)
		i18n := api.Group("/i18n")
		{
			i18n.GET("/language", authHandler.GetLanguage)
			i18n.POST("/set-language", authHandler.SetLanguage)
		}

		// Captcha routes
		captcha := api.Group("/captcha")
		{
			captcha.GET("/status", captchaHandler.GetStatus)
			captcha.POST("/generate", captchaHandler.Generate)
			captcha.POST("/verify", captchaHandler.Verify)
		}

		// Protected routes
		protected := api.Group("")
		protected.Use(middleware.AuthMiddleware(authService, cfg))
		{
			protected.GET("/auth/profile", authHandler.GetProfile)
			protected.PUT("/auth/profile", authHandler.UpdateProfile)
			protected.POST("/auth/change-password", authHandler.ChangePassword)
			protected.POST("/auth/purchase-vip", authHandler.PurchaseVIP)
			protected.POST("/auth/preview-gift-card", authHandler.PreviewGiftCard)
			protected.POST("/auth/redeem-gift-card", authHandler.RedeemGiftCard)
			protected.GET("/auth/balance", authHandler.GetBalance)
			// Signed URL routes (protected - requires authentication)
			protected.POST("/auth/signed-callback", authHandler.GenerateSignedCallback)
			// Third-party account binding status and unbind routes
			protected.GET("/auth/third-party-status", authHandler.GetThirdPartyBindingStatus)
			protected.POST("/auth/unbind/google", authHandler.UnbindGoogle)
			protected.POST("/auth/unbind/steam", authHandler.UnbindSteam)
			protected.POST("/auth/unbind/discord", authHandler.UnbindDiscord)
			// Third-party account bind routes (OAuth flow initiation)
			protected.GET("/auth/google/bind", googleHandler.GoogleBindLogin)
			protected.GET("/auth/google/bind/callback", googleHandler.GoogleBindCallback)
			protected.GET("/auth/steam/bind", steamHandler.SteamBindLogin)
			protected.GET("/auth/steam/bind/callback", steamHandler.SteamBindCallback)
			protected.GET("/auth/discord/bind", discordHandler.DiscordBindLogin)
			protected.GET("/auth/discord/bind/callback", discordHandler.DiscordBindCallback)
			// Email verification routes (protected - requires authentication)
			protected.POST("/auth/send-verification-email", authHandler.SendVerificationEmail)
			protected.POST("/auth/verify-email-code", authHandler.VerifyEmailCode)
		}

		// Payment routes
		payment := api.Group("/payment")
		{
			payment.GET("/status", paymentHandler.GetPaymentStatus)
			// Payment notification callback from external payment system (PyPay)
			// This route must be public as it's called by the payment gateway
			payment.POST("/notify", paymentHandler.PaymentNotify)
		}
		paymentProtected := api.Group("/payment")
		paymentProtected.Use(middleware.AuthMiddleware(authService, cfg))
		{
			paymentProtected.POST("/create", paymentHandler.CreatePayment)
		}
	}

	// Admin routes - Pages
	admin := r.Group("/admin")
	{
		admin.GET("/login", adminHandler.AdminLoginPage)
		admin.GET("/logout", adminHandler.AdminLogout)

		// Protected admin routes
		adminProtected := admin.Group("")
		adminProtected.Use(middleware.AdminMiddleware(authService, cfg))
		{
			adminProtected.GET("/dashboard", adminHandler.AdminDashboard)
			adminProtected.GET("/settings", adminHandler.AdminSettings)
			adminProtected.GET("/users", adminHandler.AdminUsers)
			adminProtected.GET("/vip", adminHandler.AdminVIPSettings)
			adminProtected.GET("/api-tokens", adminHandler.AdminAPITokens)
			adminProtected.GET("/gift-cards", adminHandler.AdminGiftCards)
			adminProtected.GET("/profile-navigation", adminHandler.AdminProfileNavigation)
			adminProtected.GET("/balance-logs", adminHandler.AdminBalanceLogs)
			adminProtected.GET("/login-logs", adminHandler.AdminLoginLogs)
		}
	}

	// Admin API routes
	adminAPI := r.Group("/api/admin")
	{
		adminAPI.POST("/login", adminHandler.AdminLogin)

		adminAPIProtected := adminAPI.Group("")
		adminAPIProtected.Use(middleware.AdminMiddleware(authService, cfg))
		{
			adminAPIProtected.GET("/settings", adminHandler.GetSettings)
			adminAPIProtected.PUT("/settings/google-oauth", adminHandler.UpdateGoogleOAuth)
			adminAPIProtected.PUT("/settings/steam-oauth", adminHandler.UpdateSteamOAuth)
			adminAPIProtected.PUT("/settings/discord-oauth", adminHandler.UpdateDiscordOAuth)
			adminAPIProtected.PUT("/settings/gmail-api", adminHandler.UpdateGmailAPI)
			adminAPIProtected.PUT("/settings/jwt", adminHandler.UpdateJWT)
			adminAPIProtected.PUT("/settings/captcha", adminHandler.UpdateCaptcha)
			adminAPIProtected.GET("/settings/site", adminHandler.GetSiteSettings)
			adminAPIProtected.PUT("/settings/site", adminHandler.UpdateSiteSettings)
			adminAPIProtected.GET("/settings/payment", adminHandler.GetPaymentSettings)
			adminAPIProtected.PUT("/settings/payment", adminHandler.UpdatePaymentSettings)
			adminAPIProtected.GET("/settings/vip-levels", adminHandler.GetVIPLevels)
			adminAPIProtected.PUT("/settings/vip-levels", adminHandler.UpdateVIPLevels)
			adminAPIProtected.GET("/settings/profile-navigation", adminHandler.GetProfileNavigation)
			adminAPIProtected.PUT("/settings/profile-navigation", adminHandler.UpdateProfileNavigation)
			adminAPIProtected.GET("/settings/access", adminHandler.GetAccessSettings)
			adminAPIProtected.PUT("/settings/access", adminHandler.UpdateAccessSettings)
			adminAPIProtected.GET("/settings/custom", adminHandler.GetCustomSettings)
			adminAPIProtected.PUT("/settings/custom", adminHandler.UpdateCustomSettings)
			adminAPIProtected.GET("/settings/login-protection", adminHandler.GetLoginProtectionSettings)
			adminAPIProtected.PUT("/settings/login-protection", adminHandler.UpdateLoginProtectionSettings)

			// User management routes
			adminAPIProtected.GET("/users", adminHandler.ListUsers)
			adminAPIProtected.GET("/users/:id", adminHandler.GetUser)
			adminAPIProtected.POST("/users", adminHandler.AdminCreateUser)
			adminAPIProtected.POST("/users/:id/balance", adminHandler.UpdateUserBalance)
			adminAPIProtected.PUT("/users/:id/balance", adminHandler.SetUserBalance)
			adminAPIProtected.PUT("/users/:id/vip-level", adminHandler.SetUserVIPLevel)
			adminAPIProtected.PUT("/users/:id/vip-expire", adminHandler.SetUserVIPExpireAt)
			adminAPIProtected.PUT("/users/:id/status", adminHandler.SetUserStatus)
			adminAPIProtected.POST("/users/:id/reset-password", adminHandler.ResetUserPassword)
			adminAPIProtected.POST("/users/:id/logout", adminHandler.LogoutUser)

			// API Token management routes
			adminAPIProtected.GET("/api-tokens", adminHandler.ListAPITokens)
			adminAPIProtected.POST("/api-tokens", adminHandler.CreateAPIToken)
			adminAPIProtected.DELETE("/api-tokens/:id", adminHandler.DeleteAPIToken)
			adminAPIProtected.PUT("/api-tokens/:id/toggle", adminHandler.ToggleAPIToken)

			// Gift Card management routes
			adminAPIProtected.GET("/gift-cards", adminHandler.ListGiftCards)
			adminAPIProtected.POST("/gift-cards", adminHandler.CreateGiftCards)
			adminAPIProtected.DELETE("/gift-cards/:id", adminHandler.DeleteGiftCard)
			adminAPIProtected.GET("/gift-cards/export-unused", adminHandler.ExportUnusedGiftCards)
			adminAPIProtected.POST("/gift-cards/batch-delete", adminHandler.BatchDeleteGiftCards)

			// Balance log management routes
			adminAPIProtected.GET("/balance-logs", adminHandler.ListBalanceLogs)

			// Login log management routes
			adminAPIProtected.GET("/login-logs", adminHandler.ListLoginLogs)
		}
	}

	// External API routes (token authenticated)
	externalAPI := r.Group("/api/external")
	externalAPI.Use(middleware.APITokenMiddleware(apiTokenRepo))
	{
		externalAPI.POST("/balance", adminHandler.APIUpdateBalance)
		externalAPI.POST("/vip-level", adminHandler.APISetVIPLevel)
		externalAPI.POST("/vip-expire", adminHandler.APISetVIPExpireAt)
		externalAPI.POST("/password", adminHandler.APISetPassword)
		externalAPI.GET("/user", adminHandler.APIGetUser)
		externalAPI.POST("/user", adminHandler.APICreateUser)
	}

	// Public API for frontend
	api.GET("/vip-levels", adminHandler.GetPublicVIPLevels)
	api.GET("/site-settings", adminHandler.GetPublicSiteSettings)
	api.GET("/profile-navigation", adminHandler.GetPublicProfileNavigation)
	api.GET("/custom-settings", adminHandler.GetPublicCustomSettings)

	// Swagger documentation route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Start server
	addr := cfg.Server.Host + ":" + cfg.Server.Port
	log.Printf("Starting Common Login Service on %s", addr)
	log.Printf("API Documentation: http://%s/swagger/index.html", addr)
	log.Printf("Admin panel: http://%s/admin/login", addr)
	log.Printf("Default admin credentials: %s / %s", cfg.Admin.Username, cfg.Admin.Password)

	if err := r.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
