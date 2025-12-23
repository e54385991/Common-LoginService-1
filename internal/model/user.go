package model

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	Email        string         `gorm:"uniqueIndex:idx_users_email,where:deleted_at IS NULL;size:255;not null" json:"email"`
	Username     string         `gorm:"uniqueIndex:idx_users_username,where:deleted_at IS NULL;size:100;not null" json:"username"`
	Password     string         `gorm:"size:255" json:"-"`
	DisplayName  string         `gorm:"size:100" json:"display_name"`
	Avatar       string         `gorm:"size:500" json:"avatar"`
	GoogleID     string         `gorm:"index;size:255" json:"-"`
	SteamID      string         `gorm:"index;size:255" json:"-"`
	DiscordID    string         `gorm:"index;size:255" json:"-"`
	IsActive     bool           `gorm:"default:true" json:"is_active"`
	IsAdmin      bool           `gorm:"default:false" json:"is_admin"`
	Balance      float64        `gorm:"default:0" json:"balance"`
	VIPLevel     int            `gorm:"default:0" json:"vip_level"`
	VIPExpireAt  *time.Time     `json:"vip_expire_at"`
	LastLoginAt  *time.Time     `json:"last_login_at"`
	ResetToken   string         `gorm:"size:255" json:"-"`
	ResetExpires *time.Time     `json:"-"`
}

// Session represents a user session
type Session struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	UserID    uint           `gorm:"index" json:"user_id"`
	Token     string         `gorm:"uniqueIndex;size:500" json:"token"`
	ExpiresAt time.Time      `json:"expires_at"`
	IP        string         `gorm:"size:45" json:"ip"`
	UserAgent string         `gorm:"size:500" json:"user_agent"`
}

// SystemConfig represents system configuration stored in database
type SystemConfig struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	Key       string         `gorm:"uniqueIndex;size:100" json:"key"`
	Value     string         `gorm:"type:text" json:"value"`
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	ID        uint      `gorm:"primarykey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UserID    uint      `gorm:"index" json:"user_id"`
	Token     string    `gorm:"uniqueIndex;size:255" json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Used      bool      `gorm:"default:false" json:"used"`
}

// APIToken represents an API token for external access
type APIToken struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Name        string         `gorm:"size:100" json:"name"`
	Token       string         `gorm:"uniqueIndex;size:64" json:"token"`
	Permissions string         `gorm:"size:500" json:"permissions"` // JSON array of permissions
	IsActive    bool           `gorm:"default:true" json:"is_active"`
	ExpiresAt   *time.Time     `json:"expires_at"`
	LastUsedAt  *time.Time     `json:"last_used_at"`
}

// GiftCard represents a gift card that can provide balance or VIP membership
type GiftCard struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Code        string         `gorm:"uniqueIndex;size:32" json:"code"`
	Amount      float64        `gorm:"not null" json:"amount"`
	IsUsed      bool           `gorm:"default:false" json:"is_used"`
	UsedAt      *time.Time     `json:"used_at"`
	UsedByID    *uint          `gorm:"index" json:"used_by_id"`
	ExpiresAt   *time.Time     `json:"expires_at"`
	Description string         `gorm:"size:255" json:"description"`
	VIPLevel    int            `gorm:"default:0" json:"vip_level"`  // VIP level to grant (0 = no VIP)
	VIPDays     int            `gorm:"default:0" json:"vip_days"`   // VIP duration in days (0 = permanent)
}

// PaymentOrder represents a payment order
type PaymentOrder struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	OrderID     string         `gorm:"uniqueIndex;size:64" json:"order_id"`
	UserID      uint           `gorm:"index" json:"user_id"`
	Amount      float64        `gorm:"not null" json:"amount"`
	ProductType string         `gorm:"size:32" json:"product_type"` // "vip" or "recharge"
	ProductID   int            `json:"product_id"`                  // VIP level for vip type
	Status      string         `gorm:"size:32;default:pending" json:"status"` // pending, success, fail
	PaidAt      *time.Time     `json:"paid_at"`
}

// BalanceLog represents a balance change log entry
type BalanceLog struct {
	ID            uint      `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	UserID        uint      `gorm:"index" json:"user_id"`
	Amount        float64   `gorm:"not null" json:"amount"`          // Change amount (positive or negative)
	BalanceBefore float64   `gorm:"not null" json:"balance_before"`  // Balance before change
	BalanceAfter  float64   `gorm:"not null" json:"balance_after"`   // Balance after change
	Type          string    `gorm:"size:32;index" json:"type"`       // admin, api, gift_card, purchase_vip, payment
	Reason        string    `gorm:"size:255" json:"reason"`          // Description of the change
	OperatorID    *uint     `gorm:"index" json:"operator_id"`        // Admin user ID or API token ID (if applicable)
	OperatorType  string    `gorm:"size:32" json:"operator_type"`    // admin, api_token, system, user
	RelatedID     *uint     `json:"related_id"`                      // Related entity ID (gift card ID, order ID, etc.)
}
