package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SignedUserData represents user data that can be signed and verified via HMAC
type SignedUserData struct {
	UID         uint    `json:"uid"`
	Email       string  `json:"email"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	VIPLevel    int     `json:"vip_level"`
	Balance     float64 `json:"balance"`
	Timestamp   int64   `json:"ts"`
}

// SimplifiedSignedData represents simplified user data (uid, vip_level, balance only)
// This is used for simple integration scenarios that don't need username/email/display_name
type SimplifiedSignedData struct {
	UID       uint    `json:"uid"`
	VIPLevel  int     `json:"vip_level"`
	Balance   float64 `json:"balance"`
	Timestamp int64   `json:"ts"`
}

// ComputeHMAC computes an HMAC-SHA256 signature for a single string
func ComputeHMAC(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateHMACSignature generates an HMAC-SHA256 signature for the given data
func GenerateHMACSignature(data map[string]string, secret string) string {
	// Sort keys for consistent ordering
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build the string to sign
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+data[k])
	}
	stringToSign := strings.Join(parts, "&")

	// Generate HMAC-SHA256
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyHMACSignature verifies an HMAC-SHA256 signature
func VerifyHMACSignature(data map[string]string, signature, secret string) bool {
	expectedSignature := GenerateHMACSignature(data, secret)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

// BuildSimplifiedSignedCallbackURL builds a callback URL with simplified signed user data
// Only includes uid, vip_level, balance, ts (no email, username, display_name)
func BuildSimplifiedSignedCallbackURL(baseURL, secret string, data *SimplifiedSignedData) (string, error) {
	// Parse the base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	// Build the data map with only essential fields
	dataMap := map[string]string{
		"uid":       strconv.FormatUint(uint64(data.UID), 10),
		"vip_level": strconv.Itoa(data.VIPLevel),
		"balance":   strconv.FormatFloat(data.Balance, 'f', 2, 64),
		"ts":        strconv.FormatInt(data.Timestamp, 10),
	}

	// Generate signature
	signature := GenerateHMACSignature(dataMap, secret)

	// Build query parameters
	query := parsedURL.Query()
	for k, v := range dataMap {
		query.Set(k, v)
	}
	query.Set("signature", signature)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// ParseSimplifiedSignedCallback parses and verifies a simplified signed callback URL
// Returns the simplified user data if signature is valid, error otherwise
func ParseSimplifiedSignedCallback(queryParams url.Values, secret string, maxAge time.Duration) (*SimplifiedSignedData, error) {
	// Extract signature
	signature := queryParams.Get("signature")
	if signature == "" {
		return nil, fmt.Errorf("missing signature")
	}

	// Build data map for verification (excluding signature)
	data := make(map[string]string)
	requiredFields := []string{"uid", "vip_level", "balance", "ts"}

	for _, field := range requiredFields {
		value := queryParams.Get(field)
		if value == "" {
			return nil, fmt.Errorf("missing required field: %s", field)
		}
		data[field] = value
	}

	// Verify signature
	if !VerifyHMACSignature(data, signature, secret) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Check timestamp (prevent replay attacks)
	ts, err := strconv.ParseInt(data["ts"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp")
	}

	signedTime := time.Unix(ts, 0)
	if time.Since(signedTime) > maxAge {
		return nil, fmt.Errorf("signature expired")
	}

	// Parse user data
	uid, err := strconv.ParseUint(data["uid"], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid format")
	}
	vipLevel, err := strconv.Atoi(data["vip_level"])
	if err != nil {
		return nil, fmt.Errorf("invalid vip_level format")
	}
	balance, err := strconv.ParseFloat(data["balance"], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid balance format")
	}

	return &SimplifiedSignedData{
		UID:       uint(uid),
		VIPLevel:  vipLevel,
		Balance:   balance,
		Timestamp: ts,
	}, nil
}

// BuildSignedCallbackURL builds a callback URL with signed user data
// Parameters are passed as URL query parameters with an HMAC signature
func BuildSignedCallbackURL(baseURL, secret string, userData *SignedUserData) (string, error) {
	// Parse the base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}

	// Build the data map
	data := map[string]string{
		"uid":          strconv.FormatUint(uint64(userData.UID), 10),
		"email":        userData.Email,
		"username":     userData.Username,
		"display_name": userData.DisplayName,
		"vip_level":    strconv.Itoa(userData.VIPLevel),
		"balance":      strconv.FormatFloat(userData.Balance, 'f', 2, 64),
		"ts":           strconv.FormatInt(userData.Timestamp, 10),
	}

	// Generate signature
	signature := GenerateHMACSignature(data, secret)

	// Build query parameters
	query := parsedURL.Query()
	for k, v := range data {
		query.Set(k, v)
	}
	query.Set("signature", signature)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// ParseSignedCallback parses and verifies a signed callback URL
// Returns the user data if signature is valid, error otherwise
func ParseSignedCallback(queryParams url.Values, secret string, maxAge time.Duration) (*SignedUserData, error) {
	// Extract signature
	signature := queryParams.Get("signature")
	if signature == "" {
		return nil, fmt.Errorf("missing signature")
	}

	// Build data map for verification (excluding signature)
	data := make(map[string]string)
	requiredFields := []string{"uid", "email", "username", "display_name", "vip_level", "balance", "ts"}

	for _, field := range requiredFields {
		value := queryParams.Get(field)
		if value == "" {
			return nil, fmt.Errorf("missing required field: %s", field)
		}
		data[field] = value
	}

	// Verify signature
	if !VerifyHMACSignature(data, signature, secret) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Check timestamp (prevent replay attacks)
	ts, err := strconv.ParseInt(data["ts"], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp")
	}

	signedTime := time.Unix(ts, 0)
	if time.Since(signedTime) > maxAge {
		return nil, fmt.Errorf("signature expired")
	}

	// Parse user data
	uid, err := strconv.ParseUint(data["uid"], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid format")
	}
	vipLevel, err := strconv.Atoi(data["vip_level"])
	if err != nil {
		return nil, fmt.Errorf("invalid vip_level format")
	}
	balance, err := strconv.ParseFloat(data["balance"], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid balance format")
	}

	return &SignedUserData{
		UID:         uint(uid),
		Email:       data["email"],
		Username:    data["username"],
		DisplayName: data["display_name"],
		VIPLevel:    vipLevel,
		Balance:     balance,
		Timestamp:   ts,
	}, nil
}

// EncodeUserDataToBase64 encodes user data to a base64 string with signature
// This provides a more compact representation than URL parameters
func EncodeUserDataToBase64(secret string, userData *SignedUserData) (string, error) {
	// Build the data string
	data := fmt.Sprintf("%d|%s|%s|%s|%d|%.2f|%d",
		userData.UID,
		userData.Email,
		userData.Username,
		userData.DisplayName,
		userData.VIPLevel,
		userData.Balance,
		userData.Timestamp,
	)

	// Generate signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	signature := hex.EncodeToString(h.Sum(nil))

	// Combine data and signature
	combined := data + "|" + signature

	// Base64 encode
	return base64.URLEncoding.EncodeToString([]byte(combined)), nil
}

// DecodeUserDataFromBase64 decodes and verifies user data from a base64 string
func DecodeUserDataFromBase64(encoded, secret string, maxAge time.Duration) (*SignedUserData, error) {
	// Base64 decode
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 encoding")
	}

	// Split data and signature
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 8 {
		return nil, fmt.Errorf("invalid data format")
	}

	signature := parts[7]
	data := strings.Join(parts[:7], "|")

	// Verify signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(expectedSignature), []byte(signature)) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Parse data
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid format")
	}
	vipLevel, err := strconv.Atoi(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid vip_level format")
	}
	balance, err := strconv.ParseFloat(parts[5], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid balance format")
	}
	ts, err := strconv.ParseInt(parts[6], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp format")
	}

	// Check timestamp
	signedTime := time.Unix(ts, 0)
	if time.Since(signedTime) > maxAge {
		return nil, fmt.Errorf("signature expired")
	}

	return &SignedUserData{
		UID:         uint(uid),
		Email:       parts[1],
		Username:    parts[2],
		DisplayName: parts[3],
		VIPLevel:    vipLevel,
		Balance:     balance,
		Timestamp:   ts,
	}, nil
}
