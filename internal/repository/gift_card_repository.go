package repository

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// GiftCardRepository handles gift card database operations
type GiftCardRepository struct {
	db *gorm.DB
}

// NewGiftCardRepository creates a new GiftCardRepository
func NewGiftCardRepository(db *gorm.DB) *GiftCardRepository {
	return &GiftCardRepository{db: db}
}

// GenerateCode generates a random gift card code
func GenerateCode() string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	code := make([]byte, 16)
	for i := range code {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		code[i] = charset[n.Int64()]
	}
	// Format: XXXX-XXXX-XXXX-XXXX
	return string(code[:4]) + "-" + string(code[4:8]) + "-" + string(code[8:12]) + "-" + string(code[12:])
}

// Create creates a new gift card
func (r *GiftCardRepository) Create(card *model.GiftCard) error {
	if card.Code == "" {
		card.Code = GenerateCode()
	}
	return r.db.Create(card).Error
}

// FindByCode finds a gift card by its code
func (r *GiftCardRepository) FindByCode(code string) (*model.GiftCard, error) {
	var card model.GiftCard
	err := r.db.Where("code = ?", code).First(&card).Error
	if err != nil {
		return nil, err
	}
	return &card, nil
}

// FindByID finds a gift card by ID
func (r *GiftCardRepository) FindByID(id uint) (*model.GiftCard, error) {
	var card model.GiftCard
	err := r.db.First(&card, id).Error
	if err != nil {
		return nil, err
	}
	return &card, nil
}

// List lists all gift cards with pagination
func (r *GiftCardRepository) List(page, pageSize int) ([]model.GiftCard, int64, error) {
	var cards []model.GiftCard
	var total int64

	r.db.Model(&model.GiftCard{}).Count(&total)

	offset := (page - 1) * pageSize
	err := r.db.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&cards).Error

	return cards, total, err
}

// Redeem redeems a gift card for a user
func (r *GiftCardRepository) Redeem(code string, userID uint) (*model.GiftCard, error) {
	var card model.GiftCard
	err := r.db.Where("code = ? AND is_used = ?", code, false).First(&card).Error
	if err != nil {
		return nil, err
	}

	// Check if card is expired
	if card.ExpiresAt != nil && card.ExpiresAt.Before(time.Now()) {
		return nil, gorm.ErrRecordNotFound
	}

	// Mark as used
	now := time.Now()
	card.IsUsed = true
	card.UsedAt = &now
	card.UsedByID = &userID

	if err := r.db.Save(&card).Error; err != nil {
		return nil, err
	}

	return &card, nil
}

// Delete deletes a gift card
func (r *GiftCardRepository) Delete(id uint) error {
	return r.db.Delete(&model.GiftCard{}, id).Error
}

// BatchCreate creates multiple gift cards at once
func (r *GiftCardRepository) BatchCreate(amount float64, count int, expiresAt *time.Time, description string, vipLevel int, vipDays int) ([]model.GiftCard, error) {
	cards := make([]model.GiftCard, count)
	for i := 0; i < count; i++ {
		cards[i] = model.GiftCard{
			Code:        GenerateCode(),
			Amount:      amount,
			ExpiresAt:   expiresAt,
			Description: description,
			VIPLevel:    vipLevel,
			VIPDays:     vipDays,
		}
	}

	if err := r.db.Create(&cards).Error; err != nil {
		return nil, err
	}

	return cards, nil
}

// ListUnused lists all unused gift cards
func (r *GiftCardRepository) ListUnused() ([]model.GiftCard, error) {
	var cards []model.GiftCard
	err := r.db.Where("is_used = ?", false).Order("created_at DESC").Find(&cards).Error
	return cards, err
}

// BatchDelete deletes multiple gift cards by IDs and returns the number of deleted records
func (r *GiftCardRepository) BatchDelete(ids []uint) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	result := r.db.Where("id IN ?", ids).Delete(&model.GiftCard{})
	return result.RowsAffected, result.Error
}
