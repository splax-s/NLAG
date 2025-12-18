package nlag

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	// DefaultAPIURL is the default API endpoint.
	DefaultAPIURL = "https://api.nlag.dev"
	// DefaultEdgeURL is the default edge server endpoint.
	DefaultEdgeURL = "wss://connect.nlag.dev"
	// DefaultTimeout is the default request timeout.
	DefaultTimeout = 30 * time.Second
)

// ClientConfig contains client configuration options.
type ClientConfig struct {
	// APIURL is the API endpoint (default: https://api.nlag.dev)
	APIURL string

	// EdgeURL is the edge server endpoint (default: wss://connect.nlag.dev)
	EdgeURL string

	// AuthToken is the authentication token (optional, uses stored credentials if not provided)
	AuthToken string

	// Timeout is the request timeout (default: 30s)
	Timeout time.Duration

	// AutoReconnect enables automatic reconnection (default: true)
	AutoReconnect bool

	// MaxRetries is the maximum number of reconnection attempts (default: 5)
	MaxRetries int

	// VerifyTLS enables TLS certificate verification (default: true)
	VerifyTLS bool

	// Region is the preferred region for tunnels
	Region string
}

// DefaultConfig returns the default client configuration.
func DefaultConfig() *ClientConfig {
	return &ClientConfig{
		APIURL:        DefaultAPIURL,
		EdgeURL:       DefaultEdgeURL,
		Timeout:       DefaultTimeout,
		AutoReconnect: true,
		MaxRetries:    5,
		VerifyTLS:     true,
	}
}

// Client is the NLAG client for creating tunnels.
type Client struct {
	config      *ClientConfig
	credentials *Credentials
	httpClient  *http.Client

	mu      sync.RWMutex
	tunnels []*Tunnel
}

// NewClient creates a new client with default configuration.
func NewClient() (*Client, error) {
	return NewClientWithConfig(DefaultConfig())
}

// NewClientWithConfig creates a new client with custom configuration.
func NewClientWithConfig(config *ClientConfig) (*Client, error) {
	if config == nil {
		config = DefaultConfig()
	}
	if config.APIURL == "" {
		config.APIURL = DefaultAPIURL
	}
	if config.EdgeURL == "" {
		config.EdgeURL = DefaultEdgeURL
	}
	if config.Timeout == 0 {
		config.Timeout = DefaultTimeout
	}

	// Load credentials
	var creds *Credentials
	if config.AuthToken != "" {
		creds = &Credentials{AccessToken: config.AuthToken}
	} else {
		var err error
		creds, err = LoadCredentials()
		if err != nil && err != ErrNotAuthenticated {
			return nil, fmt.Errorf("failed to load credentials: %w", err)
		}
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: config.Timeout,
	}

	return &Client{
		config:      config,
		credentials: creds,
		httpClient:  httpClient,
	}, nil
}

// Expose creates a tunnel to expose a local port.
func (c *Client) Expose(ctx context.Context, config *TunnelConfig) (*Tunnel, error) {
	if c.credentials == nil {
		return nil, ErrNotAuthenticated
	}

	if config.LocalHost == "" {
		config.LocalHost = "127.0.0.1"
	}
	if config.Protocol == "" {
		config.Protocol = ProtocolHTTP
	}

	// Request tunnel from API
	reqBody := map[string]interface{}{
		"protocol":   config.Protocol,
		"subdomain":  config.Subdomain,
		"local_port": config.LocalPort,
		"basic_auth": config.BasicAuth,
		"ip_allow":   config.IPAllow,
		"ip_deny":    config.IPDeny,
		"headers":    config.Headers,
		"region":     c.config.Region,
		"metadata":   config.Metadata,
	}

	respBody, err := c.post(ctx, "/tunnels", reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create tunnel: %w", err)
	}

	var resp struct {
		ID        string `json:"id"`
		PublicURL string `json:"public_url"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	tunnel := newTunnel(resp.ID, resp.PublicURL, config)
	tunnel.setState(StateConnected)

	c.mu.Lock()
	c.tunnels = append(c.tunnels, tunnel)
	c.mu.Unlock()

	// TODO: Start QUIC connection for data forwarding

	return tunnel, nil
}

// ListTunnels returns all active tunnels.
func (c *Client) ListTunnels(ctx context.Context) ([]*TunnelInfo, error) {
	if c.credentials == nil {
		return nil, ErrNotAuthenticated
	}

	respBody, err := c.get(ctx, "/tunnels")
	if err != nil {
		return nil, fmt.Errorf("failed to list tunnels: %w", err)
	}

	var tunnels []*TunnelInfo
	if err := json.Unmarshal(respBody, &tunnels); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return tunnels, nil
}

// GetTunnel returns information about a specific tunnel.
func (c *Client) GetTunnel(ctx context.Context, tunnelID string) (*TunnelInfo, error) {
	if c.credentials == nil {
		return nil, ErrNotAuthenticated
	}

	respBody, err := c.get(ctx, "/tunnels/"+tunnelID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tunnel: %w", err)
	}

	var tunnel TunnelInfo
	if err := json.Unmarshal(respBody, &tunnel); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &tunnel, nil
}

// CloseTunnel closes a tunnel by ID.
func (c *Client) CloseTunnel(ctx context.Context, tunnelID string) error {
	if c.credentials == nil {
		return ErrNotAuthenticated
	}

	if err := c.delete(ctx, "/tunnels/"+tunnelID); err != nil {
		return fmt.Errorf("failed to close tunnel: %w", err)
	}

	// Remove from local list
	c.mu.Lock()
	for i, t := range c.tunnels {
		if t.ID() == tunnelID {
			c.tunnels = append(c.tunnels[:i], c.tunnels[i+1:]...)
			t.Close()
			break
		}
	}
	c.mu.Unlock()

	return nil
}

// CloseAll closes all tunnels.
func (c *Client) CloseAll(ctx context.Context) error {
	c.mu.Lock()
	tunnels := make([]*Tunnel, len(c.tunnels))
	copy(tunnels, c.tunnels)
	c.tunnels = nil
	c.mu.Unlock()

	for _, t := range tunnels {
		t.Close()
	}

	return nil
}

// Config returns the client configuration.
func (c *Client) Config() *ClientConfig {
	return c.config
}

// IsAuthenticated returns true if the client has credentials.
func (c *Client) IsAuthenticated() bool {
	return c.credentials != nil
}

// SetCredentials sets the client credentials.
func (c *Client) SetCredentials(creds *Credentials) {
	c.credentials = creds
}

// get performs a GET request.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.config.APIURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	return body, nil
}

// post performs a POST request.
func (c *Client) post(ctx context.Context, path string, data interface{}) ([]byte, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.config.APIURL+path, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.credentials.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	return body, nil
}

// delete performs a DELETE request.
func (c *Client) delete(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", c.config.APIURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.credentials.AccessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	return nil
}

// httpGet performs a simple GET request (for auth).
func httpGet(url, token string) ([]byte, error) {
	client := &http.Client{Timeout: DefaultTimeout}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	return body, nil
}

// httpPost performs a simple POST request (for auth).
func httpPost(url string, data interface{}, token *string) ([]byte, error) {
	client := &http.Client{Timeout: DefaultTimeout}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != nil {
		req.Header.Set("Authorization", "Bearer "+*token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(body),
		}
	}

	return body, nil
}
