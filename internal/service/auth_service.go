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

// maxUIDRetries is the maximum number of retries when creating a user with start UID
const maxUIDRetries = 10

// AuthService handles authentication operations
type AuthService struct {
	userRepo     *repository.UserRepository
	sessionStore repository.SessionStore
	cfg          *config.Config
}

// NewAuthService creates a new AuthService
func NewAuthService(userRepo *repository.UserRepository, sessionStore repository.SessionStore, cfg *config.Config) *AuthService {
	return &AuthService{
		userRepo:     userRepo,
		sessionStore: sessionStore,
		cfg:          cfg,
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
// Email field can contain email or username depending on system configuration
type LoginInput struct {
	Email    string `json:"email" binding:"required"` // Can be email or username
	Password string `json:"password" binding:"required"`
}

// AuthResponse represents authentication response
type AuthResponse struct {
	Token string      `json:"token"`
	User  *model.User `json:"user"`
}

// createUserWithStartUID is a helper method that creates a user respecting the registration_start_uid setting.
// It handles race conditions using retry logic when start UID is configured.
func (s *AuthService) createUserWithStartUID(user *model.User) error {
	if s.cfg.Access.RegistrationStartUID > 0 {
		// Use atomic creation with retry logic to handle race conditions
		return s.userRepo.CreateWithStartUID(user, s.cfg.Access.RegistrationStartUID, maxUIDRetries)
	}
	return s.userRepo.Create(user)
}

// Register registers a new user
func (s *AuthService) Register(input *RegisterInput) (*AuthResponse, error) {
	// Validate input
	if !utils.IsValidEmail(input.Email) {
		return nil, errors.New("无效的邮箱地址")
	}
	if !utils.IsValidUsername(input.Username) {
		return nil, errors.New("用户名只能包含字母、数字和下划线，长度2-32个字符")
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

	// Create user (respects registration_start_uid if configured)
	if err := s.createUserWithStartUID(user); err != nil {
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

	// Create session record for token invalidation support
	tokenHash := utils.HashSHA256(token)
	expiresAt := time.Now().Add(time.Duration(s.cfg.JWT.ExpireHour) * time.Hour)
	session := &model.Session{
		UserID:    user.ID,
		Token:     tokenHash,
		ExpiresAt: expiresAt,
	}
	if err := s.sessionStore.Create(session); err != nil {
		// Log error but don't fail registration - session tracking is optional
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

// Login authenticates a user
func (s *AuthService) Login(input *LoginInput) (*AuthResponse, error) {
	// Determine login method based on input and configuration
	var user *model.User
	var err error
	identifier := strings.TrimSpace(input.Email)

	// Check if the identifier looks like an email
	isEmail := utils.IsValidEmail(identifier)

	if isEmail {
		// Login with email
		if !s.cfg.Access.AllowEmailLogin {
			return nil, errors.New("邮箱登录已被禁用")
		}
		user, err = s.userRepo.FindByEmail(identifier)
	} else {
		// Login with username
		if !s.cfg.Access.AllowUsernameLogin {
			return nil, errors.New("用户名登录已被禁用")
		}
		user, err = s.userRepo.FindByUsername(identifier)
	}

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errors.New("账号或密码错误")
		}
		return nil, errors.New("查询用户失败")
	}

	// Check password
	if !utils.CheckPassword(input.Password, user.Password) {
		return nil, errors.New("账号或密码错误")
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

	// Create session record for token invalidation support
	tokenHash := utils.HashSHA256(token)
	expiresAt := time.Now().Add(time.Duration(s.cfg.JWT.ExpireHour) * time.Hour)
	session := &model.Session{
		UserID:    user.ID,
		Token:     tokenHash,
		ExpiresAt: expiresAt,
	}
	if err := s.sessionStore.Create(session); err != nil {
		// Log error but don't fail login - session tracking is optional
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

		// Create user (respects registration_start_uid if configured)
		if err := s.createUserWithStartUID(user); err != nil {
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

	// Create session record for token invalidation support
	tokenHash := utils.HashSHA256(token)
	expiresAt := time.Now().Add(time.Duration(s.cfg.JWT.ExpireHour) * time.Hour)
	session := &model.Session{
		UserID:    user.ID,
		Token:     tokenHash,
		ExpiresAt: expiresAt,
	}
	if err := s.sessionStore.Create(session); err != nil {
		// Log error but don't fail login - session tracking is optional
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

// LoginWithSteam handles Steam OpenID login
func (s *AuthService) LoginWithSteam(steamID, name, avatar string) (*AuthResponse, error) {
	// Try to find user by Steam ID
	user, err := s.userRepo.FindBySteamID(steamID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("查询用户失败")
	}

	if user == nil {
		// Create new user with unique username
		baseUsername := "steam_" + steamID
		// Make username shorter if too long
		if len(baseUsername) > 26 {
			baseUsername = "steam_" + steamID[:20]
		}
		username := baseUsername
		// Make username unique using counter if exists
		counter := 1
		for s.userRepo.ExistsByUsername(username) {
			username = baseUsername + "_" + string(rune('0'+counter))
			counter++
			if counter > 9 {
				username = baseUsername + "_" + steamID[:4]
				break
			}
		}

		// Generate a placeholder email for Steam users (they don't provide email)
		// Using example.invalid as per RFC 2606 for reserved domains
		email := "steam_" + steamID + "@example.invalid"

		user = &model.User{
			Email:       email,
			Username:    username,
			DisplayName: name,
			Avatar:      avatar,
			SteamID:     steamID,
			IsActive:    true,
		}

		// Create user (respects registration_start_uid if configured)
		if err := s.createUserWithStartUID(user); err != nil {
			return nil, errors.New("创建用户失败")
		}
	} else {
		// Update avatar if provided
		if avatar != "" {
			user.Avatar = avatar
		}
		// Update display name if changed
		if name != "" && name != user.DisplayName {
			user.DisplayName = name
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

	// Create session record for token invalidation support
	tokenHash := utils.HashSHA256(token)
	expiresAt := time.Now().Add(time.Duration(s.cfg.JWT.ExpireHour) * time.Hour)
	session := &model.Session{
		UserID:    user.ID,
		Token:     tokenHash,
		ExpiresAt: expiresAt,
	}
	if err := s.sessionStore.Create(session); err != nil {
		// Log error but don't fail login - session tracking is optional
	}

	return &AuthResponse{
		Token: token,
		User:  user,
	}, nil
}

// LoginWithDiscord handles Discord OAuth login
func (s *AuthService) LoginWithDiscord(discordID, email, name, avatar string) (*AuthResponse, error) {
	// Try to find user by Discord ID
	user, err := s.userRepo.FindByDiscordID(discordID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, errors.New("查询用户失败")
	}

	if user == nil {
		// Try to find user by email if email is provided
		if email != "" {
			user, err = s.userRepo.FindByEmail(email)
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, errors.New("查询用户失败")
			}
		}
	}

	if user == nil {
		// Create new user with unique username
		baseUsername := "discord_" + discordID
		// Make username shorter if too long
		if len(baseUsername) > 26 {
			baseUsername = "discord_" + discordID[:18]
		}
		username := baseUsername
		// Make username unique using counter if exists
		counter := 1
		for s.userRepo.ExistsByUsername(username) {
			username = baseUsername + "_" + string(rune('0'+counter))
			counter++
			if counter > 9 {
				username = baseUsername + "_" + discordID[:4]
				break
			}
		}

		// Use Discord email or generate placeholder
		// Using example.invalid as per RFC 2606 for reserved domains
		userEmail := email
		if userEmail == "" {
			userEmail = "discord_" + discordID + "@example.invalid"
		}

		user = &model.User{
			Email:       userEmail,
			Username:    username,
			DisplayName: name,
			Avatar:      avatar,
			DiscordID:   discordID,
			IsActive:    true,
		}

		// Create user (respects registration_start_uid if configured)
		if err := s.createUserWithStartUID(user); err != nil {
			return nil, errors.New("创建用户失败")
		}
	} else {
		// Update Discord ID if not set
		if user.DiscordID == "" {
			user.DiscordID = discordID
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

	// Create session record for token invalidation support
	tokenHash := utils.HashSHA256(token)
	expiresAt := time.Now().Add(time.Duration(s.cfg.JWT.ExpireHour) * time.Hour)
	session := &model.Session{
		UserID:    user.ID,
		Token:     tokenHash,
		ExpiresAt: expiresAt,
	}
	if err := s.sessionStore.Create(session); err != nil {
		// Log error but don't fail login - session tracking is optional
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

	// Check if session exists (token not invalidated by logout)
	tokenHash := utils.HashSHA256(tokenString)
	_, sessionErr := s.sessionStore.FindByToken(tokenHash)
	if sessionErr != nil {
		return nil, errors.New("会话已失效，请重新登录")
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

// Logout invalidates a user's token by deleting the session
func (s *AuthService) Logout(tokenString string) error {
	tokenHash := utils.HashSHA256(tokenString)
	return s.sessionStore.Delete(tokenHash)
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

// BindGoogle binds a Google account to the current user
// Returns error if the Google ID is already bound to another user
func (s *AuthService) BindGoogle(userID uint, googleID, email, name, avatar string) error {
	// Check if binding is allowed
	if !s.cfg.GoogleOAuth.AllowBind {
		return errors.New("Google账号绑定功能已关闭")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// Check if user already has a Google ID bound
	if user.GoogleID != "" {
		return errors.New("您已绑定了Google账号")
	}

	// Check if this Google ID is already used by another user
	existingUser, err := s.userRepo.FindByGoogleID(googleID)
	if err == nil && existingUser != nil && existingUser.ID != userID {
		return errors.New("该Google账号已被其他用户绑定或注册，如需绑定请先登录该账号解绑")
	}

	// Bind Google ID to user
	user.GoogleID = googleID
	// Optionally update avatar if not set
	if user.Avatar == "" && avatar != "" {
		user.Avatar = avatar
	}

	if err := s.userRepo.Update(user); err != nil {
		return errors.New("绑定失败")
	}

	return nil
}

// UnbindGoogle unbinds Google account from the current user
func (s *AuthService) UnbindGoogle(userID uint) error {
	// Check if unbinding is allowed
	if !s.cfg.GoogleOAuth.AllowUnbind {
		return errors.New("Google账号解绑功能已关闭")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// Check if user has a Google ID bound
	if user.GoogleID == "" {
		return errors.New("您尚未绑定Google账号")
	}

	// Check if user has other login methods (password or other OAuth)
	// User must have at least one login method after unbinding
	hasPassword := user.Password != ""
	hasSteam := user.SteamID != ""
	hasDiscord := user.DiscordID != ""

	if !hasPassword && !hasSteam && !hasDiscord {
		return errors.New("解绑失败：您必须至少保留一种登录方式")
	}

	// Unbind Google ID
	user.GoogleID = ""
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("解绑失败")
	}

	return nil
}

// BindSteam binds a Steam account to the current user
// Returns error if the Steam ID is already bound to another user
func (s *AuthService) BindSteam(userID uint, steamID, name, avatar string) error {
	// Check if binding is allowed
	if !s.cfg.SteamOAuth.AllowBind {
		return errors.New("Steam账号绑定功能已关闭")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// Check if user already has a Steam ID bound
	if user.SteamID != "" {
		return errors.New("您已绑定了Steam账号")
	}

	// Check if this Steam ID is already used by another user
	existingUser, err := s.userRepo.FindBySteamID(steamID)
	if err == nil && existingUser != nil && existingUser.ID != userID {
		return errors.New("该Steam账号已被其他用户绑定或注册，如需绑定请先登录该账号解绑")
	}

	// Bind Steam ID to user
	user.SteamID = steamID
	// Optionally update avatar if not set
	if user.Avatar == "" && avatar != "" {
		user.Avatar = avatar
	}

	if err := s.userRepo.Update(user); err != nil {
		return errors.New("绑定失败")
	}

	return nil
}

// UnbindSteam unbinds Steam account from the current user
func (s *AuthService) UnbindSteam(userID uint) error {
	// Check if unbinding is allowed
	if !s.cfg.SteamOAuth.AllowUnbind {
		return errors.New("Steam账号解绑功能已关闭")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// Check if user has a Steam ID bound
	if user.SteamID == "" {
		return errors.New("您尚未绑定Steam账号")
	}

	// Check if user has other login methods
	hasPassword := user.Password != ""
	hasGoogle := user.GoogleID != ""
	hasDiscord := user.DiscordID != ""

	if !hasPassword && !hasGoogle && !hasDiscord {
		return errors.New("解绑失败：您必须至少保留一种登录方式")
	}

	// Unbind Steam ID
	user.SteamID = ""
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("解绑失败")
	}

	return nil
}

// BindDiscord binds a Discord account to the current user
// Returns error if the Discord ID is already bound to another user
func (s *AuthService) BindDiscord(userID uint, discordID, email, name, avatar string) error {
	// Check if binding is allowed
	if !s.cfg.DiscordOAuth.AllowBind {
		return errors.New("Discord账号绑定功能已关闭")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// Check if user already has a Discord ID bound
	if user.DiscordID != "" {
		return errors.New("您已绑定了Discord账号")
	}

	// Check if this Discord ID is already used by another user
	existingUser, err := s.userRepo.FindByDiscordID(discordID)
	if err == nil && existingUser != nil && existingUser.ID != userID {
		return errors.New("该Discord账号已被其他用户绑定或注册，如需绑定请先登录该账号解绑")
	}

	// Bind Discord ID to user
	user.DiscordID = discordID
	// Optionally update avatar if not set
	if user.Avatar == "" && avatar != "" {
		user.Avatar = avatar
	}

	if err := s.userRepo.Update(user); err != nil {
		return errors.New("绑定失败")
	}

	return nil
}

// UnbindDiscord unbinds Discord account from the current user
func (s *AuthService) UnbindDiscord(userID uint) error {
	// Check if unbinding is allowed
	if !s.cfg.DiscordOAuth.AllowUnbind {
		return errors.New("Discord账号解绑功能已关闭")
	}

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return errors.New("用户不存在")
	}

	// Check if user has a Discord ID bound
	if user.DiscordID == "" {
		return errors.New("您尚未绑定Discord账号")
	}

	// Check if user has other login methods
	hasPassword := user.Password != ""
	hasGoogle := user.GoogleID != ""
	hasSteam := user.SteamID != ""

	if !hasPassword && !hasGoogle && !hasSteam {
		return errors.New("解绑失败：您必须至少保留一种登录方式")
	}

	// Unbind Discord ID
	user.DiscordID = ""
	if err := s.userRepo.Update(user); err != nil {
		return errors.New("解绑失败")
	}

	return nil
}

// GetThirdPartyBindingStatus returns the current binding status for third-party accounts
func (s *AuthService) GetThirdPartyBindingStatus(userID uint) (map[string]interface{}, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, errors.New("用户不存在")
	}

	// Check if user has a password (can unbind all OAuth if password exists)
	hasPassword := user.Password != ""

	return map[string]interface{}{
		"google": map[string]interface{}{
			"bound":        user.GoogleID != "",
			"allow_bind":   s.cfg.GoogleOAuth.Enabled && s.cfg.GoogleOAuth.AllowBind,
			"allow_unbind": s.cfg.GoogleOAuth.AllowUnbind,
		},
		"steam": map[string]interface{}{
			"bound":        user.SteamID != "",
			"allow_bind":   s.cfg.SteamOAuth.Enabled && s.cfg.SteamOAuth.AllowBind,
			"allow_unbind": s.cfg.SteamOAuth.AllowUnbind,
		},
		"discord": map[string]interface{}{
			"bound":        user.DiscordID != "",
			"allow_bind":   s.cfg.DiscordOAuth.Enabled && s.cfg.DiscordOAuth.AllowBind,
			"allow_unbind": s.cfg.DiscordOAuth.AllowUnbind,
		},
		"has_password": hasPassword,
	}, nil
}
