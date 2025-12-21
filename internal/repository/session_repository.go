package repository

import (
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// SessionRepository handles session database operations
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new SessionRepository
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create creates a new session
func (r *SessionRepository) Create(session *model.Session) error {
	return r.db.Create(session).Error
}

// FindByToken finds a session by token
func (r *SessionRepository) FindByToken(token string) (*model.Session, error) {
	var session model.Session
	err := r.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&session).Error
	if err != nil {
		return nil, err
	}
	return &session, nil
}

// FindByUserID finds all sessions for a user
func (r *SessionRepository) FindByUserID(userID uint) ([]model.Session, error) {
	var sessions []model.Session
	err := r.db.Where("user_id = ?", userID).Find(&sessions).Error
	return sessions, err
}

// Delete deletes a session by token
func (r *SessionRepository) Delete(token string) error {
	return r.db.Where("token = ?", token).Delete(&model.Session{}).Error
}

// DeleteByUserID deletes all sessions for a user
func (r *SessionRepository) DeleteByUserID(userID uint) error {
	return r.db.Where("user_id = ?", userID).Delete(&model.Session{}).Error
}

// CleanExpired removes expired sessions
func (r *SessionRepository) CleanExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&model.Session{}).Error
}
