package repository

import (
	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// MessageRepository handles message database operations
type MessageRepository struct {
	db *gorm.DB
}

// NewMessageRepository creates a new MessageRepository
func NewMessageRepository(db *gorm.DB) *MessageRepository {
	return &MessageRepository{db: db}
}

// Create creates a new message
func (r *MessageRepository) Create(message *model.Message) error {
	return r.db.Create(message).Error
}

// FindByID finds a message by ID
func (r *MessageRepository) FindByID(id uint) (*model.Message, error) {
	var message model.Message
	err := r.db.First(&message, id).Error
	return &message, err
}

// FindByUserID finds messages by user ID with pagination
func (r *MessageRepository) FindByUserID(userID uint, page, pageSize int) ([]model.Message, int64, error) {
	var messages []model.Message
	var total int64

	query := r.db.Model(&model.Message{}).Where("user_id = ?", userID)
	
	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&messages).Error
	return messages, total, err
}

// FindUnreadByUserID finds unread messages by user ID
func (r *MessageRepository) FindUnreadByUserID(userID uint) ([]model.Message, error) {
	var messages []model.Message
	err := r.db.Where("user_id = ? AND is_read = ?", userID, false).
		Order("created_at DESC").Find(&messages).Error
	return messages, err
}

// CountUnreadByUserID counts unread messages by user ID
func (r *MessageRepository) CountUnreadByUserID(userID uint) (int64, error) {
	var count int64
	err := r.db.Model(&model.Message{}).Where("user_id = ? AND is_read = ?", userID, false).Count(&count).Error
	return count, err
}

// MarkAsRead marks a message as read
func (r *MessageRepository) MarkAsRead(id, userID uint) error {
	now := gorm.Expr("NOW()")
	return r.db.Model(&model.Message{}).
		Where("id = ? AND user_id = ?", id, userID).
		Updates(map[string]interface{}{
			"is_read": true,
			"read_at": now,
		}).Error
}

// MarkAllAsRead marks all messages as read for a user
func (r *MessageRepository) MarkAllAsRead(userID uint) error {
	now := gorm.Expr("NOW()")
	return r.db.Model(&model.Message{}).
		Where("user_id = ? AND is_read = ?", userID, false).
		Updates(map[string]interface{}{
			"is_read": true,
			"read_at": now,
		}).Error
}

// Delete deletes a message
func (r *MessageRepository) Delete(id, userID uint) error {
	return r.db.Where("id = ? AND user_id = ?", id, userID).Delete(&model.Message{}).Error
}

// DeleteBatch deletes multiple messages by IDs for a specific user
func (r *MessageRepository) DeleteBatch(ids []uint, userID uint) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	result := r.db.Where("id IN ? AND user_id = ?", ids, userID).Delete(&model.Message{})
	return result.RowsAffected, result.Error
}

// List lists all messages with pagination (admin)
func (r *MessageRepository) List(page, pageSize int, userID *uint) ([]model.Message, int64, error) {
	var messages []model.Message
	var total int64

	query := r.db.Model(&model.Message{})
	if userID != nil {
		query = query.Where("user_id = ?", *userID)
	}

	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&messages).Error
	return messages, total, err
}

// BatchCreate creates multiple messages in a transaction
func (r *MessageRepository) BatchCreate(messages []*model.Message) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for _, msg := range messages {
			if err := tx.Create(msg).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// MessageBatchTaskRepository handles batch task database operations
type MessageBatchTaskRepository struct {
	db *gorm.DB
}

// NewMessageBatchTaskRepository creates a new MessageBatchTaskRepository
func NewMessageBatchTaskRepository(db *gorm.DB) *MessageBatchTaskRepository {
	return &MessageBatchTaskRepository{db: db}
}

// Create creates a new batch task
func (r *MessageBatchTaskRepository) Create(task *model.MessageBatchTask) error {
	return r.db.Create(task).Error
}

// FindByID finds a batch task by ID
func (r *MessageBatchTaskRepository) FindByID(id uint) (*model.MessageBatchTask, error) {
	var task model.MessageBatchTask
	err := r.db.First(&task, id).Error
	return &task, err
}

// UpdateProgress updates the progress of a batch task
func (r *MessageBatchTaskRepository) UpdateProgress(id uint, sentCount, failedCount int, status string) error {
	updates := map[string]interface{}{
		"sent_count":   sentCount,
		"failed_count": failedCount,
		"status":       status,
	}
	if status == "completed" || status == "failed" {
		updates["completed_at"] = gorm.Expr("NOW()")
	}
	return r.db.Model(&model.MessageBatchTask{}).Where("id = ?", id).Updates(updates).Error
}

// List lists all batch tasks with pagination
func (r *MessageBatchTaskRepository) List(page, pageSize int) ([]model.MessageBatchTask, int64, error) {
	var tasks []model.MessageBatchTask
	var total int64

	query := r.db.Model(&model.MessageBatchTask{})

	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	err = query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&tasks).Error
	return tasks, total, err
}
