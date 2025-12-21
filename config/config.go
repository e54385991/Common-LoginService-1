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
	GoogleOAuth       GoogleOAuthConfig       `json:"google_oauth"`
	GmailAPI          GmailAPIConfig          `json:"gmail_api"`
	Admin             AdminConfig             `json:"admin"`
	Captcha           CaptchaConfig           `json:"captcha"`
	Site              SiteConfig              `json:"site"`
	Payment           PaymentConfig           `json:"payment"`
	VIPLevels         []VIPLevelConfig        `json:"vip_levels"`
	SignedURL         SignedURLConfig         `json:"signed_url"`
	ProfileNavigation ProfileNavigationConfig `json:"profile_navigation"`
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

// VIPLevelConfig holds VIP level configuration
type VIPLevelConfig struct {
	Level         int                `json:"level"`
	Name          string             `json:"name"`
	Description   string             `json:"description"`
	Price         float64            `json:"price"`
	Duration      int                `json:"duration"` // Duration in days, 0 = permanent
	Icon          string             `json:"icon"`
	Color         string             `json:"color"`
	UpgradePrices map[string]float64 `json:"upgrade_prices,omitempty"` // Upgrade prices from other VIP levels (key: from level as string, value: upgrade price)
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

// GoogleOAuthConfig holds Google OAuth configuration
type GoogleOAuthConfig struct {
	Enabled      bool   `json:"enabled"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
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
			GoogleOAuth: GoogleOAuthConfig{
				Enabled: false,
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
					{ID: "vip", Title: "VIP会员", Icon: "bi-gem", URL: "/recharge#vip", Type: "link", Color: "#ffd700", GradientEnd: "#ffb300", Effect: "pulse", NewTab: false, Visible: true, Order: 2},
					{ID: "settings", Title: "账号设置", Icon: "bi-gear", URL: "", Type: "action", Color: "#667eea", GradientEnd: "#764ba2", Effect: "", NewTab: false, Visible: true, Order: 3},
					{ID: "logout", Title: "退出登录", Icon: "bi-box-arrow-right", URL: "", Type: "action", Color: "#6c757d", GradientEnd: "#495057", Effect: "", NewTab: false, Visible: true, Order: 4},
				},
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
