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

// List lists all payment orders with pagination
func (r *PaymentOrderRepository) List(page, pageSize int) ([]model.PaymentOrder, int64, error) {
	var orders []model.PaymentOrder
	var total int64

	r.db.Model(&model.PaymentOrder{}).Count(&total)

	offset := (page - 1) * pageSize
	err := r.db.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&orders).Error

	return orders, total, err
}

// Search searches payment orders by order ID, user ID, or status with pagination
func (r *PaymentOrderRepository) Search(keyword string, status string, productType string, page, pageSize int) ([]model.PaymentOrder, int64, error) {
	var orders []model.PaymentOrder
	var total int64

	query := r.db.Model(&model.PaymentOrder{})

	if keyword != "" {
		// Check if keyword is numeric (potential user ID)
		query = query.Where("order_id LIKE ? OR CAST(user_id AS CHAR) LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}
	if status != "" {
		query = query.Where("status = ?", status)
	}
	if productType != "" {
		query = query.Where("product_type = ?", productType)
	}

	query.Count(&total)

	offset := (page - 1) * pageSize
	err := query.Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&orders).Error

	return orders, total, err
}

// GetStatistics returns payment order statistics
func (r *PaymentOrderRepository) GetStatistics() (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total orders
	var totalOrders int64
	r.db.Model(&model.PaymentOrder{}).Count(&totalOrders)
	stats["total_orders"] = totalOrders

	// Orders by status
	var pendingOrders int64
	r.db.Model(&model.PaymentOrder{}).Where("status = ?", PaymentStatusPending).Count(&pendingOrders)
	stats["pending_orders"] = pendingOrders

	var successOrders int64
	r.db.Model(&model.PaymentOrder{}).Where("status = ?", PaymentStatusSuccess).Count(&successOrders)
	stats["success_orders"] = successOrders

	var failedOrders int64
	r.db.Model(&model.PaymentOrder{}).Where("status = ?", PaymentStatusFail).Count(&failedOrders)
	stats["failed_orders"] = failedOrders

	// Total amount (successful orders only)
	var totalAmount float64
	r.db.Model(&model.PaymentOrder{}).Where("status = ?", PaymentStatusSuccess).Select("COALESCE(SUM(amount), 0)").Scan(&totalAmount)
	stats["total_amount"] = totalAmount

	// VIP orders total
	var vipTotal float64
	r.db.Model(&model.PaymentOrder{}).Where("status = ? AND product_type = ?", PaymentStatusSuccess, "vip").Select("COALESCE(SUM(amount), 0)").Scan(&vipTotal)
	stats["vip_total"] = vipTotal

	// Recharge orders total
	var rechargeTotal float64
	r.db.Model(&model.PaymentOrder{}).Where("status = ? AND product_type = ?", PaymentStatusSuccess, "recharge").Select("COALESCE(SUM(amount), 0)").Scan(&rechargeTotal)
	stats["recharge_total"] = rechargeTotal

	// Today's successful orders count and amount
	today := time.Now().Truncate(24 * time.Hour)
	var todayOrders int64
	r.db.Model(&model.PaymentOrder{}).Where("status = ? AND created_at >= ?", PaymentStatusSuccess, today).Count(&todayOrders)
	stats["today_orders"] = todayOrders

	var todayAmount float64
	r.db.Model(&model.PaymentOrder{}).Where("status = ? AND created_at >= ?", PaymentStatusSuccess, today).Select("COALESCE(SUM(amount), 0)").Scan(&todayAmount)
	stats["today_amount"] = todayAmount

	return stats, nil
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
