package service

import (
	"errors"
	"strings"
	"time"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/e54385991/Common-LoginService/internal/repository"
	"github.com/e54385991/Common-LoginService/pkg/utils"
	"gorm.io/gorm"
)

// AuthService handles authentication operations
type AuthService struct {
	userRepo    *repository.UserRepository
	sessionRepo *repository.SessionRepository
	cfg         *config.Config
}

// NewAuthService creates a new AuthService
func NewAuthService(userRepo *repository.UserRepository, sessionRepo *repository.SessionRepository, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		cfg:         cfg,
	}
}

// RegisterInput represents registration input
type RegisterInput struct {
	Email       string `json:"email" binding:"required,email"`
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	DisplayName string `json:"display_name"`
}

// LoginInput represents login input
type LoginInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	Token string      `json:"token"`
	User  *model.User `json:"user"`
}

// Register registers a new user
func (s *AuthService) Register(input *RegisterInput) (*AuthResponse, error) {
	// Validate input
	if !utils.IsValidEmail(input.Email) {
		return nil, errors.New("无效的邮箱地址")
	}
	if !utils.IsValidUsername(input.Username) {
		return nil, errors.New("用户名只能包含字母、数字和下划线，长度3-30个字符")
	}
	if !utils.IsValidPassword(input.Password) {
		return nil, errors.New("密码长度至少6个字符")
	}

	// Check if email exists
	if s.userRepo.ExistsByEmail(input.Email) {
		return nil, errors.New("邮箱已被注册")
	}

	// Check if username exists
	if s.userRepo.ExistsByUsername(input.Username) {
		return nil, errors.New("用户名已被使用")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return nil, errors.New("密码加密失败")
	}

	// Create user
	displayName := input.DisplayName
	if displayName == "" {
		displayName = input.Username
	}

	user := &model.User{
		Email:       input.Email,
		Username:    input.Username,
		Password:    hashedPassword,
		DisplayName: displayName,
		IsActive:    true,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, errors.New("创建用户失败")
	}

	// Generate token
	token, err := utils.GenerateJWT(
		user.ID,
		user.Email,
		user.Username,
		user.DisplayName,
		user.IsAdmin,
		s.cfg.JWT.Secret,
		s.cfg.JWT.ExpireHour,
	)
	if err != nil {
		return nil, errors.New("生成令牌失败")
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

// Login authenticates a user
func (s *AuthService) Login(input *LoginInput) (*AuthResponse, error) {
	// Find user by email
	user, err := s.userRepo.FindByEmail(input.Email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("邮箱或密码错误")
		}
		return nil, errors.New("查询用户失败")
	}

	// Check password
	if !utils.CheckPassword(input.Password, user.Password) {
		return nil, errors.New("邮箱或密码错误")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("账户已被禁用")
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	if err := s.userRepo.Update(user); err != nil {
		// Log error but don't fail login
	}

	// Generate token
	token, err := utils.GenerateJWT(
		user.ID,
		user.Email,
		user.Username,
		user.DisplayName,
		user.IsAdmin,
		s.cfg.JWT.Secret,
		s.cfg.JWT.ExpireHour,
	)
	if err != nil {
		return nil, errors.New("生成令牌失败")
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

// LoginWithGoogle handles Google OAuth login
func (s *AuthService) LoginWithGoogle(googleID, email, name, avatar string) (*AuthResponse, error) {
	// Try to find user by Google ID
	user, err := s.userRepo.FindByGoogleID(googleID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("查询用户失败")
	}

	if user == nil {
		// Try to find user by email
		user, err = s.userRepo.FindByEmail(email)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("查询用户失败")
		}
	}

	if user == nil {
		// Create new user
		// Extract username from email (handle any domain, not just gmail.com)
		atIndex := strings.Index(email, "@")
		var username string
		if atIndex > 0 {
			username = email[:atIndex]
		} else {
			username = "user_" + googleID[:8]
		}
		if len(username) < 3 {
			username = "user_" + googleID[:8]
		}
		// Make username unique if exists
		if s.userRepo.ExistsByUsername(username) {
			username = username + "_" + googleID[:4]
		}

		user = &model.User{
			Email:       email,
			Username:    username,
			DisplayName: name,
			Avatar:      avatar,
			GoogleID:    googleID,
			IsActive:    true,
		}

		if err := s.userRepo.Create(user); err != nil {
			return nil, errors.New("创建用户失败")
		}
	} else {
		// Update Google ID if not set
		if user.GoogleID == "" {
			user.GoogleID = googleID
		}
		// Update avatar if provided
		if avatar != "" {
			user.Avatar = avatar
		}
		now := time.Now()
		user.LastLoginAt = &now
		if err := s.userRepo.Update(user); err != nil {
			// Log error but don't fail login
		}
	}

	// Generate token
	token, err := utils.GenerateJWT(
		user.ID,
		user.Email,
		user.Username,
		user.DisplayName,
		user.IsAdmin,
		s.cfg.JWT.Secret,
		s.cfg.JWT.ExpireHour,
	)
	if err != nil {
		return nil, errors.New("生成令牌失败")
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

// ValidateToken validates a JWT token and returns the user
func (s *AuthService) ValidateToken(tokenString string) (*model.User, error) {
	claims, err := utils.ValidateJWT(tokenString, s.cfg.JWT.Secret)
	if err != nil {
		return nil, errors.New("无效的令牌")
	}

	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return nil, errors.New("用户不存在")
	}

	if !user.IsActive {
		return nil, errors.New("账户已被禁用")
	}

	return user, nil
}

// RequestPasswordReset initiates a password reset
func (s *AuthService) RequestPasswordReset(email string) (string, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", errors.New("该邮箱未注册")
		}
		return "", errors.New("查询用户失败")
	}

	// Generate reset token
	token, err := utils.GenerateToken(32)
	if err != nil {
		return "", errors.New("生成重置令牌失败")
	}

	// Set reset token and expiry (1 hour)
	expires := time.Now().Add(1 * time.Hour)
	user.ResetToken = token
	user.ResetExpires = &expires

	if err := s.userRepo.Update(user); err != nil {
		return "", errors.New("保存重置令牌失败")
	}

	return token, nil
}

// ResetPassword resets a user's password
func (s *AuthService) ResetPassword(token, newPassword string) error {
	if !utils.IsValidPassword(newPassword) {
		return errors.New("密码长度至少6个字符")
	}

	user, err := s.userRepo.FindByResetToken(token)
	if err != nil {
		return errors.New("无效的重置令牌")
	}

	// Check if token is expired
	if user.ResetExpires == nil || user.ResetExpires.Before(time.Now()) {
		return errors.New("重置令牌已过期")
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("密码加密失败")
	}

	// Update password and clear reset token
	user.Password = hashedPassword
	user.ResetToken = ""
	user.ResetExpires = nil

	if err := s.userRepo.Update(user); err != nil {
		return errors.New("更新密码失败")
	}

	return nil
}

// GetUserByID gets a user by ID
func (s *AuthService) GetUserByID(id uint) (*model.User, error) {
	return s.userRepo.FindByID(id)
}

// UpdateProfile updates a user's profile
func (s *AuthService) UpdateProfile(userID uint, displayName, avatar string) (*model.User, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("用户不存在")
	}

	if displayName != "" {
		user.DisplayName = displayName
	}
	if avatar != "" {
		user.Avatar = avatar
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, errors.New("更新失败")
	}

	return user, nil
}

// ChangePassword changes a user's password
func (s *AuthService) ChangePassword(userID uint, oldPassword, newPassword string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// Check if user has a password (Google OAuth users may not have one)
	if user.Password == "" {
		return errors.New("您的账户使用第三方登录，无法修改密码")
	}

	// Verify old password
	if !utils.CheckPassword(oldPassword, user.Password) {
		return errors.New("原密码错误")
	}

	// Validate new password
	if !utils.IsValidPassword(newPassword) {
		return errors.New("新密码长度至少6个字符")
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.New("密码加密失败")
	}

	// Update password
	user.Password = hashedPassword
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("更新密码失败")
	}

	return nil
}
