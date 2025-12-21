package repository

import (
	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// BalanceLogRepository handles balance log database operations
type BalanceLogRepository struct {
	db *gorm.DB
}

// NewBalanceLogRepository creates a new BalanceLogRepository
func NewBalanceLogRepository(db *gorm.DB) *BalanceLogRepository {
	return &BalanceLogRepository{db: db}
}

// Create creates a new balance log entry
func (r *BalanceLogRepository) Create(log *model.BalanceLog) error {
	return r.db.Create(log).Error
}

// List lists balance logs with pagination and optional filters
func (r *BalanceLogRepository) List(page, pageSize int, userID *uint, logType string) ([]model.BalanceLog, int64, error) {
	var logs []model.BalanceLog
	var total int64

	query := r.db.Model(&model.BalanceLog{})

	// Apply filters
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}
	if logType != "" {
		query = query.Where("type = ?", logType)
	}

	query.Count(&total)

	offset := (page - 1) * pageSize
	err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error

	return logs, total, err
}

// ListByUserID lists balance logs for a specific user with pagination
func (r *BalanceLogRepository) ListByUserID(userID uint, page, pageSize int) ([]model.BalanceLog, int64, error) {
	return r.List(page, pageSize, &userID, "")
}

// GetRecentByUserID gets recent balance logs for a specific user
func (r *BalanceLogRepository) GetRecentByUserID(userID uint, limit int) ([]model.BalanceLog, error) {
	var logs []model.BalanceLog
	err := r.db.Where("user_id = ?", userID).Order("created_at DESC").Limit(limit).Find(&logs).Error
	return logs, err
}
