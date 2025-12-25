package repository

import (
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// PasswordResetLogRepository handles password reset log database operations
type PasswordResetLogRepository struct {
	db *gorm.DB
}

// NewPasswordResetLogRepository creates a new PasswordResetLogRepository
func NewPasswordResetLogRepository(db *gorm.DB) *PasswordResetLogRepository {
	return &PasswordResetLogRepository{db: db}
}

// Create creates a new password reset log entry
func (r *PasswordResetLogRepository) Create(log *model.PasswordResetLog) error {
	return r.db.Create(log).Error
}

// CountRecentRequests counts password reset requests from an IP within the specified time window
func (r *PasswordResetLogRepository) CountRecentRequests(ip string, windowSeconds int) (int64, error) {
	var count int64
	cutoff := time.Now().Add(-time.Duration(windowSeconds) * time.Second)
	err := r.db.Model(&model.PasswordResetLog{}).
		Where("ip = ? AND created_at > ?", ip, cutoff).
		Count(&count).Error
	return count, err
}

// CanRequestPasswordReset checks if an IP can request password reset based on rate limits
// Returns true if request is allowed, and the remaining count
func (r *PasswordResetLogRepository) CanRequestPasswordReset(ip string, maxRequests int, windowSeconds int) (bool, int64, error) {
	count, err := r.CountRecentRequests(ip, windowSeconds)
	if err != nil {
		return false, 0, err
	}
	
	remaining := int64(maxRequests) - count
	if remaining < 0 {
		remaining = 0
	}
	
	return count < int64(maxRequests), remaining, nil
}

// DeleteOldLogs deletes password reset logs older than the specified number of days
func (r *PasswordResetLogRepository) DeleteOldLogs(daysToKeep int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -daysToKeep)
	result := r.db.Where("created_at < ?", cutoff).Delete(&model.PasswordResetLog{})
	return result.RowsAffected, result.Error
}
