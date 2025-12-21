package repository

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// APITokenRepository handles API token database operations
type APITokenRepository struct {
	db *gorm.DB
}

// NewAPITokenRepository creates a new APITokenRepository
func NewAPITokenRepository(db *gorm.DB) *APITokenRepository {
	return &APITokenRepository{db: db}
}

// GenerateToken generates a secure random token
func GenerateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// Create creates a new API token
func (r *APITokenRepository) Create(token *model.APIToken) error {
	if token.Token == "" {
		token.Token = GenerateToken()
	}
	return r.db.Create(token).Error
}

// FindByToken finds an API token by its token string
func (r *APITokenRepository) FindByToken(token string) (*model.APIToken, error) {
	var apiToken model.APIToken
	err := r.db.Where("token = ? AND is_active = ?", token, true).First(&apiToken).Error
	if err != nil {
		return nil, err
	}
	
	// Check if token is expired
	if apiToken.ExpiresAt != nil && apiToken.ExpiresAt.Before(time.Now()) {
		return nil, gorm.ErrRecordNotFound
	}
	
	return &apiToken, nil
}

// FindByID finds an API token by ID
func (r *APITokenRepository) FindByID(id uint) (*model.APIToken, error) {
	var apiToken model.APIToken
	err := r.db.First(&apiToken, id).Error
	if err != nil {
		return nil, err
	}
	return &apiToken, nil
}

// List lists all API tokens
func (r *APITokenRepository) List() ([]model.APIToken, error) {
	var tokens []model.APIToken
	err := r.db.Find(&tokens).Error
	return tokens, err
}

// Update updates an API token
func (r *APITokenRepository) Update(token *model.APIToken) error {
	return r.db.Save(token).Error
}

// UpdateLastUsed updates the last used timestamp
func (r *APITokenRepository) UpdateLastUsed(id uint) error {
	now := time.Now()
	return r.db.Model(&model.APIToken{}).Where("id = ?", id).Update("last_used_at", now).Error
}

// Delete deletes an API token
func (r *APITokenRepository) Delete(id uint) error {
	return r.db.Delete(&model.APIToken{}, id).Error
}
