package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// HashSHA256 creates a SHA256 hash of the input string
func HashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPassword compares a password with a hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GenerateToken generates a random token
func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// IsValidEmail validates an email address
func IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// IsValidUsername validates a username (alphanumeric and underscore, 2-32 chars)
func IsValidUsername(username string) bool {
	if len(username) < 2 || len(username) > 32 {
		return false
	}
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_]+$`)
	return usernameRegex.MatchString(username)
}

// IsValidPassword validates a password (min 6 chars) - basic validation for backward compatibility
func IsValidPassword(password string) bool {
	return len(password) >= 6
}

// PasswordValidationError represents a password validation error code
type PasswordValidationError struct {
	Code      string // Error key for i18n (e.g., "error.password_too_short")
	MinLength int    // Used for password_too_short error
}

// Error implements the error interface
func (e *PasswordValidationError) Error() string {
	return e.Code
}

// ValidatePasswordComplexity validates a password with configurable complexity rules
// Returns nil if valid, or a PasswordValidationError with error code if invalid
func ValidatePasswordComplexity(password string, minLength int, requireLetter, requireNumber, requireSpecial bool) *PasswordValidationError {
	if minLength < 1 {
		minLength = 6 // Default minimum length
	}

	if len(password) < minLength {
		return &PasswordValidationError{Code: "error.password_too_short", MinLength: minLength}
	}

	if requireLetter {
		hasLetter := false
		for _, c := range password {
			if unicode.IsLetter(c) {
				hasLetter = true
				break
			}
		}
		if !hasLetter {
			return &PasswordValidationError{Code: "error.password_require_letter"}
		}
	}

	if requireNumber {
		hasNumber := false
		for _, c := range password {
			if unicode.IsDigit(c) {
				hasNumber = true
				break
			}
		}
		if !hasNumber {
			return &PasswordValidationError{Code: "error.password_require_number"}
		}
	}

	if requireSpecial {
		hasSpecial := false
		specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
		for _, c := range password {
			if strings.ContainsRune(specialChars, c) {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial {
			return &PasswordValidationError{Code: "error.password_require_special"}
		}
	}

	return nil
}

// SanitizeString sanitizes a string for safe display
func SanitizeString(s string) string {
	// Remove potentially harmful characters
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}
