package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const defaultAPIURL = "https://api.nlag.dev"

// APIClient handles communication with the NLAG API.
type APIClient struct {
	httpClient *http.Client
	apiURL     string
	apiToken   string
	region     string
}

// NewAPIClient creates a new API client.
func NewAPIClient(apiURL, apiToken, region string) *APIClient {
	if apiURL == "" {
		apiURL = os.Getenv("NLAG_API_URL")
	}
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	if apiToken == "" {
		apiToken = os.Getenv("NLAG_API_TOKEN")
	}

	if region == "" {
		region = os.Getenv("NLAG_REGION")
	}

	return &APIClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiURL:   apiURL,
		apiToken: apiToken,
		region:   region,
	}
}

// TunnelRequest represents a request to create a tunnel.
type TunnelRequest struct {
	Protocol  string            `json:"protocol"`
	LocalPort int               `json:"local_port"`
	Subdomain string            `json:"subdomain,omitempty"`
	BasicAuth map[string]string `json:"basic_auth,omitempty"`
	IPAllow   []string          `json:"ip_allow,omitempty"`
	IPDeny    []string          `json:"ip_deny,omitempty"`
	Headers   map[string]string `json:"headers,omitempty"`
	Region    string            `json:"region,omitempty"`
	Metadata  map[string]any    `json:"metadata,omitempty"`
}

// TunnelResponse represents a tunnel from the API.
type TunnelResponse struct {
	ID           string            `json:"id"`
	PublicURL    string            `json:"public_url"`
	Protocol     string            `json:"protocol"`
	LocalAddress string            `json:"local_address"`
	State        string            `json:"state"`
	Subdomain    string            `json:"subdomain"`
	BasicAuth    map[string]string `json:"basic_auth,omitempty"`
	IPAllow      []string          `json:"ip_allow,omitempty"`
	IPDeny       []string          `json:"ip_deny,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	Metadata     map[string]any    `json:"metadata,omitempty"`
}

// DomainRequest represents a request to create a domain.
type DomainRequest struct {
	Domain      string `json:"domain"`
	TunnelID    string `json:"tunnel_id,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	PrivateKey  string `json:"private_key,omitempty"`
}

// DomainResponse represents a domain from the API.
type DomainResponse struct {
	ID              string    `json:"id"`
	Domain          string    `json:"domain"`
	Verified        bool      `json:"verified"`
	VerificationTXT string    `json:"verification_txt"`
	TunnelID        string    `json:"tunnel_id,omitempty"`
	CertExpiry      time.Time `json:"cert_expiry,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// APIKeyRequest represents a request to create an API key.
type APIKeyRequest struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
}

// APIKeyResponse represents an API key from the API.
type APIKeyResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Key         string    `json:"key,omitempty"` // Only returned on creation
	Prefix      string    `json:"prefix"`
	Permissions []string  `json:"permissions"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	LastUsedAt  time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// RegionResponse represents a region from the API.
type RegionResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Location  string `json:"location"`
	Available bool   `json:"available"`
}

// CreateTunnel creates a new tunnel.
func (c *APIClient) CreateTunnel(req TunnelRequest) (*TunnelResponse, error) {
	if req.Region == "" {
		req.Region = c.region
	}

	var resp TunnelResponse
	if err := c.post("/tunnels", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetTunnel retrieves a tunnel by ID.
func (c *APIClient) GetTunnel(id string) (*TunnelResponse, error) {
	var resp TunnelResponse
	if err := c.get("/tunnels/"+id, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// UpdateTunnel updates a tunnel.
func (c *APIClient) UpdateTunnel(id string, req TunnelRequest) (*TunnelResponse, error) {
	var resp TunnelResponse
	if err := c.put("/tunnels/"+id, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteTunnel deletes a tunnel.
func (c *APIClient) DeleteTunnel(id string) error {
	return c.delete("/tunnels/" + id)
}

// ListTunnels lists all tunnels.
func (c *APIClient) ListTunnels() ([]TunnelResponse, error) {
	var resp []TunnelResponse
	if err := c.get("/tunnels", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateDomain creates a new domain.
func (c *APIClient) CreateDomain(req DomainRequest) (*DomainResponse, error) {
	var resp DomainResponse
	if err := c.post("/domains", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetDomain retrieves a domain by ID.
func (c *APIClient) GetDomain(id string) (*DomainResponse, error) {
	var resp DomainResponse
	if err := c.get("/domains/"+id, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteDomain deletes a domain.
func (c *APIClient) DeleteDomain(id string) error {
	return c.delete("/domains/" + id)
}

// ListDomains lists all domains.
func (c *APIClient) ListDomains() ([]DomainResponse, error) {
	var resp []DomainResponse
	if err := c.get("/domains", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// CreateAPIKey creates a new API key.
func (c *APIClient) CreateAPIKey(req APIKeyRequest) (*APIKeyResponse, error) {
	var resp APIKeyResponse
	if err := c.post("/apikeys", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetAPIKey retrieves an API key by ID.
func (c *APIClient) GetAPIKey(id string) (*APIKeyResponse, error) {
	var resp APIKeyResponse
	if err := c.get("/apikeys/"+id, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteAPIKey deletes an API key.
func (c *APIClient) DeleteAPIKey(id string) error {
	return c.delete("/apikeys/" + id)
}

// ListRegions lists all available regions.
func (c *APIClient) ListRegions() ([]RegionResponse, error) {
	var resp []RegionResponse
	if err := c.get("/regions", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *APIClient) get(path string, result interface{}) error {
	req, err := http.NewRequest("GET", c.apiURL+path, nil)
	if err != nil {
		return err
	}
	return c.doRequest(req, result)
}

func (c *APIClient) post(path string, body, result interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.apiURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	return c.doRequest(req, result)
}

func (c *APIClient) put(path string, body, result interface{}) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", c.apiURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	return c.doRequest(req, result)
}

func (c *APIClient) delete(path string) error {
	req, err := http.NewRequest("DELETE", c.apiURL+path, nil)
	if err != nil {
		return err
	}
	return c.doRequest(req, nil)
}

func (c *APIClient) doRequest(req *http.Request, result interface{}) error {
	req.Header.Set("Authorization", "Bearer "+c.apiToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API error %d: %s", resp.StatusCode, string(body))
	}

	if result != nil && len(body) > 0 {
		if err := json.Unmarshal(body, result); err != nil {
			return err
		}
	}

	return nil
}
