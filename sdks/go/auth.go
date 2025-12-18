package nlag

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Credentials holds authentication information.
type Credentials struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

// IsExpired returns true if the credentials have expired.
func (c *Credentials) IsExpired() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*c.ExpiresAt)
}

// ExpiresSoon returns true if the credentials expire within 5 minutes.
func (c *Credentials) ExpiresSoon() bool {
	if c.ExpiresAt == nil {
		return false
	}
	return time.Now().Add(5 * time.Minute).After(*c.ExpiresAt)
}

// credentialsPath returns the path to the credentials file.
func credentialsPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get config directory: %w", err)
	}
	return filepath.Join(configDir, "nlag", "credentials.json"), nil
}

// LoadCredentials loads stored credentials from disk.
func LoadCredentials() (*Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotAuthenticated
		}
		return nil, fmt.Errorf("failed to read credentials: %w", err)
	}

	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	return &creds, nil
}

// SaveCredentials saves credentials to disk.
func SaveCredentials(creds *Credentials) error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}

	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	return nil
}

// DeleteCredentials removes stored credentials.
func DeleteCredentials() error {
	path, err := credentialsPath()
	if err != nil {
		return err
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete credentials: %w", err)
	}

	return nil
}

// AuthenticateOptions contains options for authentication.
type AuthenticateOptions struct {
	// API URL (default: https://api.nlag.dev)
	APIURL string
}

// Authenticate authenticates with email and password.
func Authenticate(email, password string, opts *AuthenticateOptions) (*Credentials, error) {
	if opts == nil {
		opts = &AuthenticateOptions{}
	}
	if opts.APIURL == "" {
		opts.APIURL = DefaultAPIURL
	}

	// Make login request
	resp, err := httpPost(opts.APIURL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	}, nil)
	if err != nil {
		return nil, err
	}

	var authResp struct {
		AccessToken  string     `json:"access_token"`
		RefreshToken string     `json:"refresh_token"`
		ExpiresAt    *time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(resp, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	creds := &Credentials{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		ExpiresAt:    authResp.ExpiresAt,
	}

	// Save for future use
	if err := SaveCredentials(creds); err != nil {
		// Log but don't fail
		fmt.Fprintf(os.Stderr, "Warning: failed to save credentials: %v\n", err)
	}

	return creds, nil
}

// AuthenticateWithToken authenticates using an API token.
func AuthenticateWithToken(token string, opts *AuthenticateOptions) (*Credentials, error) {
	if opts == nil {
		opts = &AuthenticateOptions{}
	}
	if opts.APIURL == "" {
		opts.APIURL = DefaultAPIURL
	}

	// Validate token by calling /auth/me
	_, err := httpGet(opts.APIURL+"/auth/me", token)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	creds := &Credentials{
		AccessToken: token,
	}

	if err := SaveCredentials(creds); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save credentials: %v\n", err)
	}

	return creds, nil
}

// RefreshToken refreshes an access token using the refresh token.
func RefreshToken(refreshToken string, opts *AuthenticateOptions) (*Credentials, error) {
	if opts == nil {
		opts = &AuthenticateOptions{}
	}
	if opts.APIURL == "" {
		opts.APIURL = DefaultAPIURL
	}

	resp, err := httpPost(opts.APIURL+"/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, nil)
	if err != nil {
		return nil, err
	}

	var authResp struct {
		AccessToken  string     `json:"access_token"`
		RefreshToken string     `json:"refresh_token"`
		ExpiresAt    *time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(resp, &authResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	creds := &Credentials{
		AccessToken:  authResp.AccessToken,
		RefreshToken: authResp.RefreshToken,
		ExpiresAt:    authResp.ExpiresAt,
	}

	if err := SaveCredentials(creds); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save credentials: %v\n", err)
	}

	return creds, nil
}

// Logout removes stored credentials.
func Logout() error {
	return DeleteCredentials()
}
