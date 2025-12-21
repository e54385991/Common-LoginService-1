package repository

import (
	"strings"

	"github.com/e54385991/Common-LoginService/internal/model"
	"gorm.io/gorm"
)

// UserRepository handles user database operations
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(user *model.User) error {
	return r.db.Create(user).Error
}

// FindByID finds a user by ID
func (r *UserRepository) FindByID(id uint) (*model.User, error) {
	var user model.User
	err := r.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByEmail finds a user by email
func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	var user model.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByUsername finds a user by username
func (r *UserRepository) FindByUsername(username string) (*model.User, error) {
	var user model.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByGoogleID finds a user by Google ID
func (r *UserRepository) FindByGoogleID(googleID string) (*model.User, error) {
	var user model.User
	err := r.db.Where("google_id = ?", googleID).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByResetToken finds a user by reset token
func (r *UserRepository) FindByResetToken(token string) (*model.User, error) {
	var user model.User
	err := r.db.Where("reset_token = ?", token).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// Update updates a user
func (r *UserRepository) Update(user *model.User) error {
	return r.db.Save(user).Error
}

// Delete deletes a user
func (r *UserRepository) Delete(id uint) error {
	return r.db.Delete(&model.User{}, id).Error
}

// List lists all users with pagination
func (r *UserRepository) List(page, pageSize int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	r.db.Model(&model.User{}).Count(&total)

	offset := (page - 1) * pageSize
	err := r.db.Offset(offset).Limit(pageSize).Find(&users).Error

	return users, total, err
}

// Search searches users by username, email, or display name with pagination
func (r *UserRepository) Search(keyword string, page, pageSize int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	query := r.db.Model(&model.User{})
	
	if keyword != "" {
		// Escape special SQL LIKE characters to prevent SQL injection
		escapedKeyword := strings.ReplaceAll(keyword, "\\", "\\\\")
		escapedKeyword = strings.ReplaceAll(escapedKeyword, "%", "\\%")
		escapedKeyword = strings.ReplaceAll(escapedKeyword, "_", "\\_")
		searchPattern := "%" + escapedKeyword + "%"
		query = query.Where("username LIKE ? OR email LIKE ? OR display_name LIKE ?", searchPattern, searchPattern, searchPattern)
	}

	query.Count(&total)

	offset := (page - 1) * pageSize
	err := query.Offset(offset).Limit(pageSize).Find(&users).Error

	return users, total, err
}

// ExistsByEmail checks if a user exists by email
func (r *UserRepository) ExistsByEmail(email string) bool {
	var count int64
	r.db.Model(&model.User{}).Where("email = ?", email).Count(&count)
	return count > 0
}

// ExistsByUsername checks if a user exists by username
func (r *UserRepository) ExistsByUsername(username string) bool {
	var count int64
	r.db.Model(&model.User{}).Where("username = ?", username).Count(&count)
	return count > 0
}

// UpdateBalance updates the user's balance by a given amount (can be positive or negative)
// Uses atomic database operation to prevent race conditions
func (r *UserRepository) UpdateBalance(id uint, amount float64) (*model.User, error) {
	// Use atomic update to prevent race conditions
	result := r.db.Model(&model.User{}).Where("id = ?", id).Update("balance", gorm.Expr("balance + ?", amount))
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	
	// Fetch the updated user
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// SetBalance sets the user's balance to a specific value
func (r *UserRepository) SetBalance(id uint, balance float64) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	
	user.Balance = balance
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// SetVIPLevel sets the user's VIP level
func (r *UserRepository) SetVIPLevel(id uint, level int) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	
	user.VIPLevel = level
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// SetUserStatus sets the user's active status
func (r *UserRepository) SetUserStatus(id uint, isActive bool) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	
	user.IsActive = isActive
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// ResetPassword resets a user's password to the given hashed password
func (r *UserRepository) ResetPassword(id uint, hashedPassword string) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	
	user.Password = hashedPassword
	user.ResetToken = ""
	user.ResetExpires = nil
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}
