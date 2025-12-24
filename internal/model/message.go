package model

import (
	"time"

	"gorm.io/gorm"
)

// Message represents a user message
type Message struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	UserID    uint           `gorm:"index;not null" json:"user_id"`    // Recipient user ID
	Title     string         `gorm:"size:255;not null" json:"title"`   // Message title
	Content   string         `gorm:"type:text;not null" json:"content"` // Message content
	IsRead    bool           `gorm:"default:false;index" json:"is_read"` // Whether message has been read
	ReadAt    *time.Time     `json:"read_at"`                           // When message was read
	SenderID  *uint          `gorm:"index" json:"sender_id"`            // Admin user ID who sent the message (null for system)
	Type      string         `gorm:"size:32;default:normal;index" json:"type"` // Message type: normal, system, announcement
}

// MessageBatchTask represents a batch message sending task
type MessageBatchTask struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	Title       string         `gorm:"size:255;not null" json:"title"`   // Message title
	Content     string         `gorm:"type:text;not null" json:"content"` // Message content
	Type        string         `gorm:"size:32;default:normal" json:"type"` // Message type
	TotalUsers  int            `gorm:"default:0" json:"total_users"`       // Total number of users to send to
	SentCount   int            `gorm:"default:0" json:"sent_count"`        // Number of messages sent
	FailedCount int            `gorm:"default:0" json:"failed_count"`      // Number of failed sends
	Status      string         `gorm:"size:32;default:pending;index" json:"status"` // pending, running, completed, failed
	CreatedBy   *uint          `gorm:"index" json:"created_by"`            // Admin user ID who created the task
	CompletedAt *time.Time     `json:"completed_at"`                       // When task was completed
}
