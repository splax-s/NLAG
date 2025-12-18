package nlag

import (
	"errors"
	"fmt"
)

// Error types for the NLAG SDK.
var (
	// ErrNotAuthenticated is returned when no credentials are available.
	ErrNotAuthenticated = errors.New("not authenticated")

	// ErrInvalidCredentials is returned when credentials are invalid.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrTokenExpired is returned when the access token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrRateLimited is returned when API rate limit is exceeded.
	ErrRateLimited = errors.New("rate limited")

	// ErrQuotaExceeded is returned when the account quota is exceeded.
	ErrQuotaExceeded = errors.New("quota exceeded")

	// ErrTunnelNotFound is returned when a tunnel cannot be found.
	ErrTunnelNotFound = errors.New("tunnel not found")

	// ErrTunnelClosed is returned when operating on a closed tunnel.
	ErrTunnelClosed = errors.New("tunnel closed")

	// ErrConnectionFailed is returned when connection to edge fails.
	ErrConnectionFailed = errors.New("connection failed")

	// ErrTimeout is returned when an operation times out.
	ErrTimeout = errors.New("operation timed out")
)

// APIError represents an error returned by the NLAG API.
type APIError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
	Code       string `json:"code,omitempty"`
	Details    string `json:"details,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("API error %d [%s]: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error is a 404 Not Found.
func (e *APIError) IsNotFound() bool {
	return e.StatusCode == 404
}

// IsUnauthorized returns true if the error is a 401 Unauthorized.
func (e *APIError) IsUnauthorized() bool {
	return e.StatusCode == 401
}

// IsForbidden returns true if the error is a 403 Forbidden.
func (e *APIError) IsForbidden() bool {
	return e.StatusCode == 403
}

// IsRateLimited returns true if the error is a 429 Too Many Requests.
func (e *APIError) IsRateLimited() bool {
	return e.StatusCode == 429
}

// IsServerError returns true if the error is a 5xx server error.
func (e *APIError) IsServerError() bool {
	return e.StatusCode >= 500 && e.StatusCode < 600
}

// ConnectionError represents a connection failure.
type ConnectionError struct {
	Addr    string
	Cause   error
	Retries int
}

// Error implements the error interface.
func (e *ConnectionError) Error() string {
	if e.Retries > 0 {
		return fmt.Sprintf("connection to %s failed after %d retries: %v", e.Addr, e.Retries, e.Cause)
	}
	return fmt.Sprintf("connection to %s failed: %v", e.Addr, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ConnectionError) Unwrap() error {
	return e.Cause
}

// ConfigError represents a configuration error.
type ConfigError struct {
	Field   string
	Message string
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return fmt.Sprintf("configuration error for %s: %s", e.Field, e.Message)
}
