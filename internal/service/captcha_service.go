package service

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// CaptchaService handles captcha operations
type CaptchaService struct {
	captchas map[string]*CaptchaData
	mu       sync.RWMutex
}

// CaptchaData stores captcha information
type CaptchaData struct {
	ID        string    `json:"id"`
	Target    int       `json:"target"`    // Target position (0-100)
	CreatedAt time.Time `json:"-"`
	Verified  bool      `json:"-"`
}

// CaptchaResponse is returned when generating a captcha
type CaptchaResponse struct {
	ID     string `json:"id"`
	Target int    `json:"target"` // Target position for slider
}

// NewCaptchaService creates a new CaptchaService
func NewCaptchaService() *CaptchaService {
	cs := &CaptchaService{
		captchas: make(map[string]*CaptchaData),
	}
	// Start cleanup goroutine
	go cs.cleanup()
	return cs
}

// Generate creates a new captcha
func (s *CaptchaService) Generate() (*CaptchaResponse, error) {
	// Generate random ID
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idBytes)

	// Generate random target position (20-80 to avoid edges)
	targetBytes := make([]byte, 1)
	if _, err := rand.Read(targetBytes); err != nil {
		return nil, err
	}
	target := 20 + int(targetBytes[0])%61 // Range: 20-80

	captcha := &CaptchaData{
		ID:        id,
		Target:    target,
		CreatedAt: time.Now(),
		Verified:  false,
	}

	s.mu.Lock()
	s.captchas[id] = captcha
	s.mu.Unlock()

	return &CaptchaResponse{
		ID:     id,
		Target: target,
	}, nil
}

// Verify checks if the captcha answer is correct
func (s *CaptchaService) Verify(id string, position int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	captcha, exists := s.captchas[id]
	if !exists {
		return false
	}

	// Check if captcha is expired (5 minutes)
	if time.Since(captcha.CreatedAt) > 5*time.Minute {
		delete(s.captchas, id)
		return false
	}

	// Check if already used
	if captcha.Verified {
		delete(s.captchas, id)
		return false
	}

	// Allow tolerance of 5 units
	tolerance := 5
	if position >= captcha.Target-tolerance && position <= captcha.Target+tolerance {
		captcha.Verified = true
		// Mark as used but keep for a short time to prevent replay
		go func() {
			time.Sleep(30 * time.Second)
			s.mu.Lock()
			delete(s.captchas, id)
			s.mu.Unlock()
		}()
		return true
	}

	return false
}

// IsVerified checks if a captcha has been verified
func (s *CaptchaService) IsVerified(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	captcha, exists := s.captchas[id]
	if !exists {
		return false
	}

	return captcha.Verified
}

// cleanup removes expired captchas
func (s *CaptchaService) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		s.mu.Lock()
		for id, captcha := range s.captchas {
			if time.Since(captcha.CreatedAt) > 10*time.Minute {
				delete(s.captchas, id)
			}
		}
		s.mu.Unlock()
	}
}
