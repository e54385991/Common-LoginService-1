package repository

import (
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// RegistrationLogRepository handles registration log database operations
type RegistrationLogRepository struct {
	db *gorm.DB
}

// NewRegistrationLogRepository creates a new RegistrationLogRepository
func NewRegistrationLogRepository(db *gorm.DB) *RegistrationLogRepository {
	return &RegistrationLogRepository{db: db}
}

// Create creates a new registration log entry
func (r *RegistrationLogRepository) Create(log *model.RegistrationLog) error {
	return r.db.Create(log).Error
}

// CountRecentRegistrations counts registrations from an IP within the specified time window
func (r *RegistrationLogRepository) CountRecentRegistrations(ip string, windowSeconds int) (int64, error) {
	var count int64
	cutoff := time.Now().Add(-time.Duration(windowSeconds) * time.Second)
	err := r.db.Model(&model.RegistrationLog{}).
		Where("ip = ? AND success = ? AND created_at > ?", ip, true, cutoff).
		Count(&count).Error
	return count, err
}

// CanRegister checks if an IP can register based on rate limits
// Returns true if registration is allowed, and the remaining count
func (r *RegistrationLogRepository) CanRegister(ip string, maxRegistrations int, windowSeconds int) (bool, int64, error) {
	count, err := r.CountRecentRegistrations(ip, windowSeconds)
	if err != nil {
		return false, 0, err
	}
	
	remaining := int64(maxRegistrations) - count
	if remaining < 0 {
		remaining = 0
	}
	
	return count < int64(maxRegistrations), remaining, nil
}

// DeleteOldLogs deletes registration logs older than the specified number of days
func (r *RegistrationLogRepository) DeleteOldLogs(daysToKeep int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -daysToKeep)
	result := r.db.Where("created_at < ?", cutoff).Delete(&model.RegistrationLog{})
	return result.RowsAffected, result.Error
}
