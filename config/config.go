package config

import (
	"encoding/json"
	"os"
	"sync"
)

// Config holds all application configuration
type Config struct {
	Server            ServerConfig            `json:"server"`
	Database          DatabaseConfig          `json:"database"`
	JWT               JWTConfig               `json:"jwt"`
	Session           SessionConfig           `json:"session"`
	GoogleOAuth       GoogleOAuthConfig       `json:"google_oauth"`
	SteamOAuth        SteamOAuthConfig        `json:"steam_oauth"`
	DiscordOAuth      DiscordOAuthConfig      `json:"discord_oauth"`
	GmailAPI          GmailAPIConfig          `json:"gmail_api"`
	Admin             AdminConfig             `json:"admin"`
	Captcha           CaptchaConfig           `json:"captcha"`
	Site              SiteConfig              `json:"site"`
	Custom            CustomConfig            `json:"custom"`
	Access            AccessConfig            `json:"access"`
	Payment           PaymentConfig           `json:"payment"`
	VIPLevels         []VIPLevelConfig        `json:"vip_levels"`
	SignedURL         SignedURLConfig         `json:"signed_url"`
	ProfileNavigation ProfileNavigationConfig `json:"profile_navigation"`
	LoginProtection   LoginProtectionConfig   `json:"login_protection"`
}

// LoginProtectionConfig holds configuration for login protection (IP-based rate limiting)
type LoginProtectionConfig struct {
	Enabled        bool `json:"enabled"`         // Whether login protection is enabled
	MaxAttempts    int  `json:"max_attempts"`    // Maximum failed login attempts before freeze
	FreezeSeconds  int  `json:"freeze_seconds"`  // Duration in seconds to freeze the IP after max attempts
	WindowSeconds  int  `json:"window_seconds"`  // Time window in seconds to count failed attempts
}

// ProfileNavigationConfig holds configuration for profile page navigation items
type ProfileNavigationConfig struct {
	Items []ProfileNavItem `json:"items"`
}

// ProfileNavItem represents a single navigation item in the profile page
type ProfileNavItem struct {
	ID          string `json:"id"`           // Unique identifier
	Title       string `json:"title"`        // Display title
	Icon        string `json:"icon"`         // Bootstrap icon class (e.g., "bi-star")
	URL         string `json:"url"`          // Link URL (optional, for links)
	Type        string `json:"type"`         // "link", "button", or "action"
	Color       string `json:"color"`        // Background color (e.g., "#667eea")
	GradientEnd string `json:"gradient_end"` // Gradient end color (optional)
	Effect      string `json:"effect"`       // Button effect: "pulse", "glow", "bounce", or empty
	NewTab      bool   `json:"new_tab"`      // Open in new tab
	Visible     bool   `json:"visible"`      // Whether the item is visible
	Order       int    `json:"order"`        // Display order
}

// SignedURLConfig holds configuration for HMAC-signed URL callback feature
type SignedURLConfig struct {
	Enabled       bool   `json:"enabled"`
	Secret        string `json:"secret"`          // HMAC secret key for signing
	ExpireSeconds int    `json:"expire_seconds"`  // Signature expiration time in seconds (default: 300)
}

// SiteConfig holds website configuration
type SiteConfig struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Logo        string `json:"logo"`
	DarkMode    string `json:"dark_mode"` // Dark mode setting: "system" (follow system), "dark" (always dark), "light" (always light)
}

// CustomConfig holds custom HTML/CSS and footer text configuration
type CustomConfig struct {
	GlobalCSS  string `json:"global_css"`  // Custom CSS to inject in all pages
	GlobalHTML string `json:"global_html"` // Custom HTML to inject in all pages (e.g., analytics scripts)
	FooterText string `json:"footer_text"` // Custom footer text (supports HTML)
}

// AccessConfig holds access control configuration for registration and login
type AccessConfig struct {
	RegistrationEnabled        bool   `json:"registration_enabled"`
	LoginEnabled               bool   `json:"login_enabled"`
	RegistrationMessage        string `json:"registration_message"`         // Custom message when registration is disabled
	LoginMessage               string `json:"login_message"`                // Custom message when login is disabled
	RegistrationStartUID       uint   `json:"registration_start_uid"`       // Minimum UID for backend registration (0 = no restriction)
	AllowEmailLogin            bool   `json:"allow_email_login"`            // Allow login with email (default: true)
	AllowUsernameLogin         bool   `json:"allow_username_login"`         // Allow login with username (default: false)
	RequireEmailVerification   bool   `json:"require_email_verification"`   // Require email verification for new users
}

// PaymentConfig holds payment gateway configuration
type PaymentConfig struct {
	Enabled    bool   `json:"enabled"`
	DemoMode   bool   `json:"demo_mode"`
	ApiURL     string `json:"api_url"`
	MerchantID string `json:"merchant_id"`
	ApiKey     string `json:"api_key"`
	NotifyURL  string `json:"notify_url"`
	ReturnURL  string `json:"return_url"`
}

// VIPSpecification holds a specific duration/price option for a VIP level
type VIPSpecification struct {
	Duration      int                `json:"duration"`                 // Duration in days, 0 = permanent
	Price         float64            `json:"price"`                    // Price for this duration
	UpgradePrices map[string]float64 `json:"upgrade_prices,omitempty"` // Upgrade prices from other VIP levels (key: from level as string, value: upgrade price)
}

// VIPFeature holds a single feature for a VIP level
type VIPFeature struct {
	Text    string `json:"text"`    // Feature description text
	Enabled bool   `json:"enabled"` // Whether this feature is enabled for this VIP level
}

// VIPLevelConfig holds VIP level configuration
type VIPLevelConfig struct {
	Level          int                `json:"level"`
	Name           string             `json:"name"`
	Description    string             `json:"description"`
	Price          float64            `json:"price"`                     // Default price (kept for backward compatibility)
	Duration       int                `json:"duration"`                  // Default duration in days, 0 = permanent (kept for backward compatibility)
	Icon           string             `json:"icon"`
	Color          string             `json:"color"`
	Features       []VIPFeature       `json:"features,omitempty"`        // List of features for this VIP level
	UpgradePrices  map[string]float64 `json:"upgrade_prices,omitempty"`  // Upgrade prices from other VIP levels (key: from level as string, value: upgrade price) (kept for backward compatibility)
	Specifications []VIPSpecification `json:"specifications,omitempty"`  // Multiple duration/price options for this VIP level
}

// CaptchaConfig holds captcha configuration
type CaptchaConfig struct {
	Enabled bool `json:"enabled"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port string `json:"port"`
	Host string `json:"host"`
}

// DatabaseConfig holds MySQL database configuration
type DatabaseConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	DBName   string `json:"dbname"`
	Charset  string `json:"charset"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret     string `json:"secret"`
	ExpireHour int    `json:"expire_hour"`
}

// SessionConfig holds session storage configuration
type SessionConfig struct {
	// Storage type: "mysql" or "redis" (default: "mysql")
	StorageType string `json:"storage_type"`
	// Redis configuration (only used when storage_type is "redis")
	Redis RedisConfig `json:"redis"`
}

// RedisConfig holds Redis connection configuration
type RedisConfig struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
	// Key prefix for session keys in Redis
	KeyPrefix string `json:"key_prefix"`
}

// GoogleOAuthConfig holds Google OAuth configuration
type GoogleOAuthConfig struct {
	Enabled         bool   `json:"enabled"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	RedirectURL     string `json:"redirect_url"`
	BindRedirectURL string `json:"bind_redirect_url"` // Redirect URL for account binding (if different from login)
	AllowBind       bool   `json:"allow_bind"`        // Allow users to bind Google account in profile
	AllowUnbind     bool   `json:"allow_unbind"`      // Allow users to unbind Google account in profile
}

// SteamOAuthConfig holds Steam OpenID configuration
type SteamOAuthConfig struct {
	Enabled         bool   `json:"enabled"`
	APIKey          string `json:"api_key"`
	RedirectURL     string `json:"redirect_url"`
	BindRedirectURL string `json:"bind_redirect_url"` // Redirect URL for account binding (if different from login)
	AllowBind       bool   `json:"allow_bind"`        // Allow users to bind Steam account in profile
	AllowUnbind     bool   `json:"allow_unbind"`      // Allow users to unbind Steam account in profile
}

// DiscordOAuthConfig holds Discord OAuth configuration
type DiscordOAuthConfig struct {
	Enabled         bool   `json:"enabled"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	RedirectURL     string `json:"redirect_url"`
	BindRedirectURL string `json:"bind_redirect_url"` // Redirect URL for account binding (if different from login)
	AllowBind       bool   `json:"allow_bind"`        // Allow users to bind Discord account in profile
	AllowUnbind     bool   `json:"allow_unbind"`      // Allow users to unbind Discord account in profile
}

// GmailAPIConfig holds Gmail API configuration
type GmailAPIConfig struct {
	Enabled         bool   `json:"enabled"`
	CredentialsFile string `json:"credentials_file"`
	TokenFile       string `json:"token_file"`
	SenderEmail     string `json:"sender_email"`
	// OAuth2 credentials for Gmail API
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// AdminConfig holds admin configuration
type AdminConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var (
	cfg  *Config
	once sync.Once
)

// GetDSN returns the MySQL DSN string
func (d *DatabaseConfig) GetDSN() string {
	return d.User + ":" + d.Password + "@tcp(" + d.Host + ":" + d.Port + ")/" + d.DBName + "?charset=" + d.Charset + "&parseTime=True&loc=Local"
}

// Load loads configuration from file or environment
func Load(configPath string) (*Config, error) {
	var err error
	once.Do(func() {
		cfg = &Config{
			Server: ServerConfig{
				Port: "8080",
				Host: "0.0.0.0",
			},
			Database: DatabaseConfig{
				Host:     "127.0.0.1",
				Port:     "3306",
				User:     "root",
				Password: "",
				DBName:   "login_service",
				Charset:  "utf8mb4",
			},
			JWT: JWTConfig{
				Secret:     "your-secret-key-change-in-production",
				ExpireHour: 24,
			},
			Session: SessionConfig{
				StorageType: "mysql",
				Redis: RedisConfig{
					Host:      "127.0.0.1",
					Port:      "6379",
					Password:  "",
					DB:        0,
					KeyPrefix: "session:",
				},
			},
			GoogleOAuth: GoogleOAuthConfig{
				Enabled:     false,
				AllowBind:   true,
				AllowUnbind: true,
			},
			SteamOAuth: SteamOAuthConfig{
				Enabled:     false,
				AllowBind:   true,
				AllowUnbind: true,
			},
			DiscordOAuth: DiscordOAuthConfig{
				Enabled:     false,
				AllowBind:   true,
				AllowUnbind: true,
			},
			GmailAPI: GmailAPIConfig{
				Enabled: false,
			},
			Admin: AdminConfig{
				Username: "admin",
				Password: "admin123",
			},
			Captcha: CaptchaConfig{
				Enabled: false,
			},
			Site: SiteConfig{
				Title:       "Common Login Service",
				Description: "统一身份认证服务",
				Logo:        "",
				DarkMode:    "system", // Default: follow system preference
			},
			Custom: CustomConfig{
				GlobalCSS:  "",
				GlobalHTML: "",
				FooterText: "",
			},
			Access: AccessConfig{
				RegistrationEnabled:        true,
				LoginEnabled:               true,
				RegistrationMessage:        "",
				LoginMessage:               "",
				RegistrationStartUID:       0,     // 0 = no restriction, set to e.g. 26000 to start UIDs from that value
				AllowEmailLogin:            true,  // Allow login with email by default
				AllowUsernameLogin:         false, // Allow login with username, disabled by default
				RequireEmailVerification:   false, // Require email verification for new users, disabled by default
			},
			Payment: PaymentConfig{
				Enabled:    false,
				DemoMode:   true,
				ApiURL:     "https://pypay.meilanyv.cn/api/",
				MerchantID: "",
				ApiKey:     "",
				NotifyURL:  "",
				ReturnURL:  "",
			},
			VIPLevels: []VIPLevelConfig{
				{Level: 1, Name: "VIP 1", Description: "享受基础特权：去除广告、专属标识", Price: 9.9, Duration: 30, Icon: "bi-star", Color: "#cd7f32"},
				{Level: 2, Name: "VIP 2", Description: "享受进阶特权：优先客服、专属折扣", Price: 29.9, Duration: 30, Icon: "bi-star-fill", Color: "#c0c0c0"},
				{Level: 3, Name: "VIP 3", Description: "享受尊贵特权：全部功能、专属活动", Price: 99.9, Duration: 30, Icon: "bi-gem", Color: "#ffd700"},
			},
			SignedURL: SignedURLConfig{
				Enabled:       false,
				Secret:        "",
				ExpireSeconds: 300, // 5 minutes default
			},
			ProfileNavigation: ProfileNavigationConfig{
				Items: []ProfileNavItem{
					{ID: "recharge", Title: "充值中心", Icon: "bi-wallet2", URL: "/recharge", Type: "link", Color: "#28a745", GradientEnd: "#20c997", Effect: "glow", NewTab: false, Visible: true, Order: 1},
					{ID: "vip", Title: "VIP会员", Icon: "bi-gem", URL: "/vip", Type: "link", Color: "#ffd700", GradientEnd: "#ffb300", Effect: "pulse", NewTab: false, Visible: true, Order: 2},
					{ID: "settings", Title: "账号设置", Icon: "bi-gear", URL: "", Type: "action", Color: "#667eea", GradientEnd: "#764ba2", Effect: "", NewTab: false, Visible: true, Order: 3},
					{ID: "logout", Title: "退出登录", Icon: "bi-box-arrow-right", URL: "", Type: "action", Color: "#6c757d", GradientEnd: "#495057", Effect: "", NewTab: false, Visible: true, Order: 4},
				},
			},
			LoginProtection: LoginProtectionConfig{
				Enabled:       false,
				MaxAttempts:   5,              // 5 failed attempts
				FreezeSeconds: 300,            // 5 minutes freeze
				WindowSeconds: 600,            // 10 minutes window to count failures
			},
		}

		if configPath != "" {
			var file *os.File
			file, err = os.Open(configPath)
			if err == nil {
				defer file.Close()
				decoder := json.NewDecoder(file)
				err = decoder.Decode(cfg)
			} else if os.IsNotExist(err) {
				err = nil // Use default config if file doesn't exist
			}
		}

		// Override with environment variables
		if port := os.Getenv("SERVER_PORT"); port != "" {
			cfg.Server.Port = port
		}
		if secret := os.Getenv("JWT_SECRET"); secret != "" {
			cfg.JWT.Secret = secret
		}
		if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
			cfg.GoogleOAuth.ClientID = clientID
			cfg.GoogleOAuth.Enabled = true
		}
		if clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET"); clientSecret != "" {
			cfg.GoogleOAuth.ClientSecret = clientSecret
		}
		// Database environment variables
		if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
			cfg.Database.Host = dbHost
		}
		if dbPort := os.Getenv("DB_PORT"); dbPort != "" {
			cfg.Database.Port = dbPort
		}
		if dbUser := os.Getenv("DB_USER"); dbUser != "" {
			cfg.Database.User = dbUser
		}
		if dbPassword := os.Getenv("DB_PASSWORD"); dbPassword != "" {
			cfg.Database.Password = dbPassword
		}
		if dbName := os.Getenv("DB_NAME"); dbName != "" {
			cfg.Database.DBName = dbName
		}
		// Signed URL environment variables
		if signedURLSecret := os.Getenv("SIGNED_URL_SECRET"); signedURLSecret != "" {
			cfg.SignedURL.Secret = signedURLSecret
			cfg.SignedURL.Enabled = true
		}
		// Session storage environment variables
		if sessionStorageType := os.Getenv("SESSION_STORAGE_TYPE"); sessionStorageType != "" {
			cfg.Session.StorageType = sessionStorageType
		}
		if redisHost := os.Getenv("REDIS_HOST"); redisHost != "" {
			cfg.Session.Redis.Host = redisHost
		}
		if redisPort := os.Getenv("REDIS_PORT"); redisPort != "" {
			cfg.Session.Redis.Port = redisPort
		}
		if redisPassword := os.Getenv("REDIS_PASSWORD"); redisPassword != "" {
			cfg.Session.Redis.Password = redisPassword
		}
		if redisKeyPrefix := os.Getenv("REDIS_KEY_PREFIX"); redisKeyPrefix != "" {
			cfg.Session.Redis.KeyPrefix = redisKeyPrefix
		}
	})
	return cfg, err
}

// Get returns the current configuration
func Get() *Config {
	if cfg == nil {
		cfg, _ = Load("")
	}
	return cfg
}

// Save saves configuration to file
func Save(configPath string) error {
	file, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(cfg)
}

// Update updates the configuration
func Update(newConfig *Config) {
	cfg = newConfig
}
