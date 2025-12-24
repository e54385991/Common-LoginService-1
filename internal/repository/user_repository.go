package repository

import (
	"errors"
	"strconv"
	"strings"
	"time"

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

// FindBySteamID finds a user by Steam ID
func (r *UserRepository) FindBySteamID(steamID string) (*model.User, error) {
	var user model.User
	err := r.db.Where("steam_id = ?", steamID).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindByDiscordID finds a user by Discord ID
func (r *UserRepository) FindByDiscordID(discordID string) (*model.User, error) {
	var user model.User
	err := r.db.Where("discord_id = ?", discordID).First(&user).Error
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

// Search searches users by username, email, display name, or user ID with pagination
func (r *UserRepository) Search(keyword string, page, pageSize int) ([]model.User, int64, error) {
	var users []model.User
	var total int64

	query := r.db.Model(&model.User{})
	
	if keyword != "" {
		// Check if keyword is a numeric ID
		if id, err := strconv.ParseUint(keyword, 10, 32); err == nil {
			// Search by user ID (exact match)
			query = query.Where("id = ?", uint(id))
		} else {
			// Escape special SQL LIKE characters to prevent SQL injection
			escapedKeyword := strings.ReplaceAll(keyword, "\\", "\\\\")
			escapedKeyword = strings.ReplaceAll(escapedKeyword, "%", "\\%")
			escapedKeyword = strings.ReplaceAll(escapedKeyword, "_", "\\_")
			searchPattern := "%" + escapedKeyword + "%"
			query = query.Where("username LIKE ? OR email LIKE ? OR display_name LIKE ?", searchPattern, searchPattern, searchPattern)
		}
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

// SetVIPExpireAt sets the user's VIP expiration time
func (r *UserRepository) SetVIPExpireAt(id uint, expireAt *time.Time) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	
	user.VIPExpireAt = expireAt
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// SetVIPLevelWithDuration sets the user's VIP level and calculates expiration based on duration
// If duration is 0, the VIP is permanent (no expiration)
// If duration > 0, expiration is set to now + duration days
func (r *UserRepository) SetVIPLevelWithDuration(id uint, level int, durationDays int) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	
	user.VIPLevel = level
	if durationDays > 0 {
		expireAt := time.Now().AddDate(0, 0, durationDays)
		user.VIPExpireAt = &expireAt
	} else {
		// Permanent VIP - no expiration
		user.VIPExpireAt = nil
	}
	
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// SetVIPLevelWithUpgrade sets the user's VIP level with time compensation for upgrades.
// When upgrading from an existing VIP with remaining time, the remaining time is converted
// and added to the new VIP duration based on the price ratio.
//
// Parameters:
//   - id: user ID
//   - level: new VIP level
//   - durationDays: base duration for the new VIP level (0 = permanent)
//   - oldPrice: price of the old VIP level (for time conversion ratio)
//   - newPrice: price of the new VIP level (for time conversion ratio)
//
// Time conversion formula: convertedDays = remainingDays * (oldPrice / newPrice)
// The converted days are rounded to the nearest integer and added to the base duration.
//
// Returns the updated user and the number of bonus days added from conversion.
func (r *UserRepository) SetVIPLevelWithUpgrade(id uint, level int, durationDays int, oldPrice float64, newPrice float64) (*model.User, int, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, 0, err
	}
	
	bonusDays := 0
	
	// Calculate remaining days from current VIP if not expired and has valid expiration
	if user.VIPLevel > 0 && user.VIPExpireAt != nil && user.VIPExpireAt.After(time.Now()) {
		remainingDuration := user.VIPExpireAt.Sub(time.Now())
		// Use integer division for whole days, then add partial day if remaining hours >= 12
		remainingWholeDays := int(remainingDuration / (24 * time.Hour))
		remainingHours := int(remainingDuration.Hours()) % 24
		remainingDays := float64(remainingWholeDays)
		if remainingHours >= 12 {
			remainingDays += 1.0 // Round up partial day
		}
		
		// Convert remaining days to new VIP level equivalent based on price ratio
		// If old VIP was cheaper, the remaining time converts to fewer days at the new level
		// If prices are same, 1:1 conversion
		// Skip conversion if prices are invalid (zero or negative)
		if newPrice > 0 && oldPrice > 0 {
			convertedDays := remainingDays * (oldPrice / newPrice)
			// Round to nearest integer for fair conversion
			bonusDays = int(convertedDays + 0.5)
		}
	}
	
	user.VIPLevel = level
	if durationDays > 0 || bonusDays > 0 {
		totalDays := durationDays + bonusDays
		if totalDays > 0 {
			expireAt := time.Now().AddDate(0, 0, totalDays)
			user.VIPExpireAt = &expireAt
		} else {
			user.VIPExpireAt = nil
		}
	} else {
		// Permanent VIP - no expiration
		user.VIPExpireAt = nil
	}
	
	if err := r.db.Save(&user).Error; err != nil {
		return nil, 0, err
	}
	return &user, bonusDays, nil
}

// RenewVIPLevel renews/extends the user's VIP membership.
// If the user already has an active VIP (not expired), the duration is added to the current expiration time.
// If the VIP has expired or the user has no VIP, the duration is added from the current time.
// If duration is 0, the VIP becomes permanent (no expiration).
// The level parameter is optional - if 0, it keeps the current level (must be > 0 already).
func (r *UserRepository) RenewVIPLevel(id uint, level int, durationDays int) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}

	// Set VIP level if provided, otherwise keep current level
	if level > 0 {
		user.VIPLevel = level
	}

	if durationDays > 0 {
		var baseTime time.Time
		// If user has active VIP with valid expiration, add to existing time
		if user.VIPExpireAt != nil && user.VIPExpireAt.After(time.Now()) {
			baseTime = *user.VIPExpireAt
		} else {
			// Start from now if expired or no expiration
			baseTime = time.Now()
		}
		expireAt := baseTime.AddDate(0, 0, durationDays)
		user.VIPExpireAt = &expireAt
	} else {
		// Permanent VIP - no expiration
		user.VIPExpireAt = nil
	}

	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// CheckAndExpireVIP checks if VIP has expired and resets if necessary
// Returns true if VIP was expired, false otherwise
func (r *UserRepository) CheckAndExpireVIP(user *model.User) (bool, error) {
	if user.VIPLevel == 0 {
		return false, nil
	}
	
	// If no expiration date, VIP is permanent
	if user.VIPExpireAt == nil {
		return false, nil
	}
	
	// Check if expired
	if time.Now().After(*user.VIPExpireAt) {
		// VIP has expired - reset to level 0
		user.VIPLevel = 0
		user.VIPExpireAt = nil
		if err := r.db.Save(user).Error; err != nil {
			return false, err
		}
		return true, nil
	}
	
	return false, nil
}

// CreateWithID creates a new user with a specific ID
func (r *UserRepository) CreateWithID(user *model.User) error {
	return r.db.Create(user).Error
}

// ExistsByID checks if a user exists by ID using efficient query
func (r *UserRepository) ExistsByID(id uint) bool {
	var user model.User
	err := r.db.Select("id").Where("id = ?", id).First(&user).Error
	return err == nil
}

// GetMaxID returns the maximum user ID in the database, or 0 if no users exist
func (r *UserRepository) GetMaxID() (uint, error) {
	var maxID *uint
	err := r.db.Model(&model.User{}).Select("MAX(id)").Scan(&maxID).Error
	if err != nil {
		return 0, err
	}
	if maxID == nil {
		return 0, nil
	}
	return *maxID, nil
}

// CreateWithStartUID creates a new user with an ID >= startUID.
// It handles race conditions by retrying with incremented IDs if creation fails due to duplicate ID.
// The maxRetries parameter controls how many times to retry before giving up.
func (r *UserRepository) CreateWithStartUID(user *model.User, startUID uint, maxRetries int) error {
	maxID, err := r.GetMaxID()
	if err != nil {
		return err
	}

	// Calculate the starting point for the new UID
	nextUID := maxID + 1
	if nextUID < startUID {
		nextUID = startUID
	}

	// Try to create with retry logic to handle race conditions
	for attempt := 0; attempt < maxRetries; attempt++ {
		candidateID := nextUID + uint(attempt)
		user.ID = candidateID
		err := r.db.Create(user).Error
		if err == nil {
			return nil // Success
		}
		// Check if error is due to duplicate key - if so, retry with next ID
		// MySQL error 1062 is "Duplicate entry", SQLite uses "UNIQUE constraint failed"
		// We check for common duplicate key error patterns
		errStr := err.Error()
		if !isDuplicateKeyError(errStr) {
			// Reset user.ID to 0 on non-duplicate errors so caller knows creation failed
			user.ID = 0
			return err
		}
		// Duplicate key error - reset ID and retry with next ID
		user.ID = 0
	}

	return errors.New("failed to create user after max retries due to ID conflicts")
}

// isDuplicateKeyError checks if an error is a duplicate key violation
func isDuplicateKeyError(errStr string) bool {
	// MySQL: "Error 1062: Duplicate entry" or just "Duplicate entry"
	// SQLite: "UNIQUE constraint failed"
	// PostgreSQL: "duplicate key value violates unique constraint"
	return strings.Contains(errStr, "Duplicate entry") ||
		strings.Contains(errStr, "UNIQUE constraint failed") ||
		strings.Contains(errStr, "duplicate key value")
}

// SetEmailVerified sets the user's email verification status
func (r *UserRepository) SetEmailVerified(id uint, verified bool) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}

	user.EmailVerified = verified
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// UpdateEmail updates the user's email address and resets verification status
func (r *UserRepository) UpdateEmail(id uint, email string) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}

	user.Email = email
	user.EmailVerified = false
	if err := r.db.Save(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}
