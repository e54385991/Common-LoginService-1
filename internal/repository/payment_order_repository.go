package repository

import (
	"time"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// Payment order status constants
const (
	PaymentStatusPending = "pending"
	PaymentStatusSuccess = "success"
	PaymentStatusFail    = "fail"
)

// PaymentOrderRepository handles payment order database operations
type PaymentOrderRepository struct {
	db *gorm.DB
}

// NewPaymentOrderRepository creates a new PaymentOrderRepository
func NewPaymentOrderRepository(db *gorm.DB) *PaymentOrderRepository {
	return &PaymentOrderRepository{db: db}
}

// Create creates a new payment order
func (r *PaymentOrderRepository) Create(order *model.PaymentOrder) error {
	return r.db.Create(order).Error
}

// FindByOrderID finds a payment order by order ID
func (r *PaymentOrderRepository) FindByOrderID(orderID string) (*model.PaymentOrder, error) {
	var order model.PaymentOrder
	err := r.db.Where("order_id = ?", orderID).First(&order).Error
	if err != nil {
		return nil, err
	}
	return &order, nil
}

// MarkAsSuccess marks a payment order as successful
// Returns true if the order was updated, false if it was already processed
// Uses atomic update to prevent race conditions and duplicate processing
func (r *PaymentOrderRepository) MarkAsSuccess(orderID string) (bool, *model.PaymentOrder, error) {
	now := time.Now()
	
	// Use atomic update: only update if status is still "pending"
	result := r.db.Model(&model.PaymentOrder{}).
		Where("order_id = ? AND status = ?", orderID, PaymentStatusPending).
		Updates(map[string]interface{}{
			"status":  PaymentStatusSuccess,
			"paid_at": now,
		})
	
	if result.Error != nil {
		return false, nil, result.Error
	}
	
	// If no rows affected, order was already processed or doesn't exist
	if result.RowsAffected == 0 {
		// Check if order exists
		order, err := r.FindByOrderID(orderID)
		if err != nil {
			return false, nil, err
		}
		// Order exists but already processed
		return false, order, nil
	}
	
	// Fetch the updated order
	order, err := r.FindByOrderID(orderID)
	if err != nil {
		return false, nil, err
	}
	
	return true, order, nil
}

// MarkAsFail marks a payment order as failed
func (r *PaymentOrderRepository) MarkAsFail(orderID string) error {
	return r.db.Model(&model.PaymentOrder{}).
		Where("order_id = ? AND status = ?", orderID, PaymentStatusPending).
		Update("status", PaymentStatusFail).Error
}

// RevertToPending reverts a payment order back to pending status
// Used when payment processing fails after marking as success
func (r *PaymentOrderRepository) RevertToPending(orderID string) error {
	return r.db.Model(&model.PaymentOrder{}).
		Where("order_id = ? AND status = ?", orderID, PaymentStatusSuccess).
		Updates(map[string]interface{}{
			"status":  PaymentStatusPending,
			"paid_at": nil,
		}).Error
}
