package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/e54385991/Common-LoginService/config"
	"github.com/e54385991/Common-LoginService/internal/model"
	"github.com/redis/go-redis/v9"
)

// ErrSessionNotFound is returned when a session is not found
var ErrSessionNotFound = errors.New("session not found")

// SessionStore defines the interface for session storage
type SessionStore interface {
	// Create creates a new session
	Create(session *model.Session) error
	// FindByToken finds a session by token hash
	FindByToken(token string) (*model.Session, error)
	// FindByUserID finds all sessions for a user
	FindByUserID(userID uint) ([]model.Session, error)
	// Delete deletes a session by token hash
	Delete(token string) error
	// DeleteByUserID deletes all sessions for a user
	DeleteByUserID(userID uint) error
	// CleanExpired removes expired sessions
	CleanExpired() error
}

// RedisSessionStore implements SessionStore using Redis
type RedisSessionStore struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedisSessionStore creates a new Redis session store
func NewRedisSessionStore(cfg *config.RedisConfig) (*RedisSessionStore, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Host + ":" + cfg.Port,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "session:"
	}

	return &RedisSessionStore{
		client:    client,
		keyPrefix: keyPrefix,
	}, nil
}

// sessionData represents the session data stored in Redis
type sessionData struct {
	ID        uint      `json:"id"`
	UserID    uint      `json:"user_id"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
}

// Create creates a new session in Redis using a pipeline for atomicity
func (r *RedisSessionStore) Create(session *model.Session) error {
	ctx := context.Background()

	// Calculate TTL
	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return errors.New("session has already expired")
	}

	data := sessionData{
		ID:        session.ID,
		UserID:    session.UserID,
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
		IP:        session.IP,
		UserAgent: session.UserAgent,
		CreatedAt: session.CreatedAt,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	tokenKey := r.keyPrefix + "token:" + session.Token
	userKey := r.keyPrefix + "user:" + uintToString(session.UserID)

	// Use pipeline for atomic operations
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, tokenKey, jsonData, ttl)
	pipe.SAdd(ctx, userKey, session.Token)

	_, err = pipe.Exec(ctx)
	return err
}

// FindByToken finds a session by token hash
func (r *RedisSessionStore) FindByToken(token string) (*model.Session, error) {
	ctx := context.Background()

	tokenKey := r.keyPrefix + "token:" + token
	jsonData, err := r.client.Get(ctx, tokenKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	var data sessionData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return nil, err
	}

	// Check if session has expired
	if data.ExpiresAt.Before(time.Now()) {
		// Clean up expired session (best effort, ignore errors)
		_ = r.Delete(token)
		return nil, ErrSessionNotFound
	}

	return &model.Session{
		ID:        data.ID,
		UserID:    data.UserID,
		Token:     data.Token,
		ExpiresAt: data.ExpiresAt,
		IP:        data.IP,
		UserAgent: data.UserAgent,
		CreatedAt: data.CreatedAt,
	}, nil
}

// FindByUserID finds all sessions for a user
func (r *RedisSessionStore) FindByUserID(userID uint) ([]model.Session, error) {
	ctx := context.Background()

	userKey := r.keyPrefix + "user:" + uintToString(userID)
	tokens, err := r.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return nil, err
	}

	var sessions []model.Session
	var expiredTokens []interface{}

	for _, token := range tokens {
		session, err := r.FindByToken(token)
		if err != nil {
			if err == ErrSessionNotFound {
				// Token may have expired, collect for batch removal
				expiredTokens = append(expiredTokens, token)
				continue
			}
			return nil, err
		}
		sessions = append(sessions, *session)
	}

	// Remove expired tokens from user's set (best effort)
	if len(expiredTokens) > 0 {
		_ = r.client.SRem(ctx, userKey, expiredTokens...).Err()
	}

	return sessions, nil
}

// Delete deletes a session by token hash using a pipeline for atomicity
func (r *RedisSessionStore) Delete(token string) error {
	ctx := context.Background()

	// First get the session to find the user ID
	tokenKey := r.keyPrefix + "token:" + token
	jsonData, err := r.client.Get(ctx, tokenKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			// Token doesn't exist, nothing to delete
			return nil
		}
		return err
	}

	var data sessionData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		// If we can't parse the data, just delete the token key
		return r.client.Del(ctx, tokenKey).Err()
	}

	// Use pipeline for atomic deletion
	userKey := r.keyPrefix + "user:" + uintToString(data.UserID)
	pipe := r.client.TxPipeline()
	pipe.Del(ctx, tokenKey)
	pipe.SRem(ctx, userKey, token)

	_, err = pipe.Exec(ctx)
	return err
}

// DeleteByUserID deletes all sessions for a user using a pipeline for atomicity
func (r *RedisSessionStore) DeleteByUserID(userID uint) error {
	ctx := context.Background()

	userKey := r.keyPrefix + "user:" + uintToString(userID)
	tokens, err := r.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return err
	}

	if len(tokens) == 0 {
		// No sessions to delete
		return nil
	}

	// Use pipeline to delete all token keys and user set atomically
	pipe := r.client.TxPipeline()
	for _, token := range tokens {
		tokenKey := r.keyPrefix + "token:" + token
		pipe.Del(ctx, tokenKey)
	}
	pipe.Del(ctx, userKey)

	_, err = pipe.Exec(ctx)
	return err
}

// CleanExpired is a no-op for Redis as TTL handles expiration
func (r *RedisSessionStore) CleanExpired() error {
	// Redis automatically removes expired keys via TTL
	return nil
}

// Close closes the Redis connection
func (r *RedisSessionStore) Close() error {
	return r.client.Close()
}

// uintToString converts uint to string
func uintToString(n uint) string {
	return strconv.FormatUint(uint64(n), 10)
}
