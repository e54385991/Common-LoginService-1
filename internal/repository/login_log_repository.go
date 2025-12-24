package repository

import (
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// LoginLogRepository handles login log database operations
type LoginLogRepository struct {
	db *gorm.DB
}

// NewLoginLogRepository creates a new LoginLogRepository
func NewLoginLogRepository(db *gorm.DB) *LoginLogRepository {
	return &LoginLogRepository{db: db}
}

// Create creates a new login log entry
func (r *LoginLogRepository) Create(log *model.LoginLog) error {
	return r.db.Create(log).Error
}

// CountRecentFailedAttempts counts failed login attempts from an IP within the specified time window
func (r *LoginLogRepository) CountRecentFailedAttempts(ip string, windowSeconds int) (int64, error) {
	var count int64
	cutoff := time.Now().Add(-time.Duration(windowSeconds) * time.Second)
	err := r.db.Model(&model.LoginLog{}).
		Where("ip = ? AND success = ? AND created_at > ?", ip, false, cutoff).
		Count(&count).Error
	return count, err
}

// GetLastFailedAttemptTime returns the time of the last failed login attempt from an IP
func (r *LoginLogRepository) GetLastFailedAttemptTime(ip string) (*time.Time, error) {
	var log model.LoginLog
	err := r.db.Where("ip = ? AND success = ?", ip, false).
		Order("created_at DESC").
		First(&log).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &log.CreatedAt, nil
}

// List returns login logs with pagination and optional filters
func (r *LoginLogRepository) List(page, pageSize int, ip string, success *bool, username string, userID *uint) ([]model.LoginLog, int64, error) {
	var logs []model.LoginLog
	var total int64

	query := r.db.Model(&model.LoginLog{})

	// Apply filters
	if ip != "" {
		query = query.Where("ip = ?", ip)
	}
	if success != nil {
		query = query.Where("success = ?", *success)
	}
	if username != "" {
		query = query.Where("username LIKE ?", "%"+username+"%")
	}
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}

	// Count total
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	offset := (page - 1) * pageSize
	err := query.Order("created_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&logs).Error

	return logs, total, err
}

// DeleteOldLogs deletes login logs older than the specified number of days
func (r *LoginLogRepository) DeleteOldLogs(daysToKeep int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -daysToKeep)
	result := r.db.Where("created_at < ?", cutoff).Delete(&model.LoginLog{})
	return result.RowsAffected, result.Error
}

// IsIPFrozen checks if an IP is currently frozen due to too many failed attempts
// Returns true if frozen, and the remaining freeze duration in seconds
func (r *LoginLogRepository) IsIPFrozen(ip string, maxAttempts int, windowSeconds int, freezeSeconds int) (bool, int, error) {
	// Count recent failed attempts
	count, err := r.CountRecentFailedAttempts(ip, windowSeconds)
	if err != nil {
		return false, 0, err
	}

	// If not enough failed attempts, not frozen
	if count < int64(maxAttempts) {
		return false, 0, nil
	}

	// Get time of last failed attempt to calculate freeze expiry
	lastFailedTime, err := r.GetLastFailedAttemptTime(ip)
	if err != nil {
		return false, 0, err
	}
	if lastFailedTime == nil {
		return false, 0, nil
	}

	// Calculate freeze expiry time
	freezeExpiry := lastFailedTime.Add(time.Duration(freezeSeconds) * time.Second)
	now := time.Now()

	// If freeze has expired, not frozen
	if now.After(freezeExpiry) {
		return false, 0, nil
	}

	// Calculate remaining freeze time
	remainingSeconds := int(freezeExpiry.Sub(now).Seconds())
	return true, remainingSeconds, nil
}
