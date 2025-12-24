package repository

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// EmailVerificationRepository handles email verification token operations
type EmailVerificationRepository struct {
	db *gorm.DB
}

// NewEmailVerificationRepository creates a new EmailVerificationRepository
func NewEmailVerificationRepository(db *gorm.DB) *EmailVerificationRepository {
	return &EmailVerificationRepository{db: db}
}

// GenerateVerificationCode generates a 6-digit verification code (100000-999999)
func GenerateVerificationCode() (string, error) {
	// Generate number in range 0-899999, then add 100000 to get 100000-999999
	max := big.NewInt(900000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("failed to generate verification code: %w", err)
	}
	code := n.Int64() + 100000
	return fmt.Sprintf("%d", code), nil
}

// Create creates a new email verification code
func (r *EmailVerificationRepository) Create(userID uint, email string) (*model.EmailVerificationToken, error) {
	code, err := GenerateVerificationCode()
	if err != nil {
		return nil, err
	}

	token := &model.EmailVerificationToken{
		UserID:    userID,
		Email:     email,
		Token:     code,
		ExpiresAt: time.Now().Add(30 * time.Minute), // 30 minutes validity
		Used:      false,
	}

	if err := r.db.Create(token).Error; err != nil {
		return nil, err
	}

	return token, nil
}

// ErrVerificationCodeGenerationFailed is returned when verification code generation fails
var ErrVerificationCodeGenerationFailed = errors.New("failed to generate verification code")

// FindByToken finds a verification token by its token string
func (r *EmailVerificationRepository) FindByToken(token string) (*model.EmailVerificationToken, error) {
	var verifyToken model.EmailVerificationToken
	err := r.db.Where("token = ? AND used = ? AND expires_at > ?", token, false, time.Now()).First(&verifyToken).Error
	if err != nil {
		return nil, err
	}
	return &verifyToken, nil
}

// FindByUserIDAndCode finds a verification code by user ID and code string
func (r *EmailVerificationRepository) FindByUserIDAndCode(userID uint, code string) (*model.EmailVerificationToken, error) {
	var verifyToken model.EmailVerificationToken
	err := r.db.Where("user_id = ? AND token = ? AND used = ? AND expires_at > ?", userID, code, false, time.Now()).First(&verifyToken).Error
	if err != nil {
		return nil, err
	}
	return &verifyToken, nil
}

// MarkUsed marks a verification token as used
func (r *EmailVerificationRepository) MarkUsed(id uint) error {
	return r.db.Model(&model.EmailVerificationToken{}).Where("id = ?", id).Update("used", true).Error
}

// GetLastTokenTime gets the time of the last verification token sent to a user
func (r *EmailVerificationRepository) GetLastTokenTime(userID uint) (*time.Time, error) {
	var token model.EmailVerificationToken
	err := r.db.Where("user_id = ?", userID).Order("created_at DESC").First(&token).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &token.CreatedAt, nil
}

// CanSendVerificationEmail checks if enough time has passed since last verification email (60 seconds)
func (r *EmailVerificationRepository) CanSendVerificationEmail(userID uint) (bool, int, error) {
	lastTime, err := r.GetLastTokenTime(userID)
	if err != nil {
		return false, 0, err
	}
	if lastTime == nil {
		return true, 0, nil
	}
	
	elapsed := time.Since(*lastTime)
	waitSeconds := 60
	if elapsed < time.Duration(waitSeconds)*time.Second {
		remaining := waitSeconds - int(elapsed.Seconds())
		return false, remaining, nil
	}
	
	return true, 0, nil
}

// DeleteExpired deletes expired verification tokens
func (r *EmailVerificationRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ? OR used = ?", time.Now(), true).Delete(&model.EmailVerificationToken{}).Error
}
