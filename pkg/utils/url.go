package utils

import (
	"strings"

	"github.com/gin-gonic/gin"
)

// GetBaseURL returns the base URL for the site.
// If configuredBaseURL is set, it uses that; otherwise, it auto-detects from the request.
// The configuredBaseURL should be in format like "https://user.yuelk.com" (without trailing slash).
func GetBaseURL(c *gin.Context, configuredBaseURL string) string {
	// If a base URL is configured, use it
	if configuredBaseURL != "" {
		// Remove trailing slash if present for consistency
		return strings.TrimSuffix(configuredBaseURL, "/")
	}

	// Auto-detect from request
	scheme := "http"
	if c.Request.TLS != nil ||
		c.GetHeader("X-Forwarded-Proto") == "https" ||
		c.GetHeader("X-Forwarded-Ssl") == "on" ||
		c.GetHeader("X-Url-Scheme") == "https" {
		scheme = "https"
	}

	return scheme + "://" + c.Request.Host
}
