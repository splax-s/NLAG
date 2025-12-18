package nlag

import (
	"sync"
	"sync/atomic"
	"time"
)

// Protocol represents the tunnel protocol.
type Protocol string

const (
	// ProtocolHTTP is HTTP protocol.
	ProtocolHTTP Protocol = "http"
	// ProtocolHTTPS is HTTPS protocol.
	ProtocolHTTPS Protocol = "https"
	// ProtocolTCP is raw TCP protocol.
	ProtocolTCP Protocol = "tcp"
	// ProtocolUDP is raw UDP protocol.
	ProtocolUDP Protocol = "udp"
	// ProtocolGRPC is gRPC protocol.
	ProtocolGRPC Protocol = "grpc"
	// ProtocolWebSocket is WebSocket protocol.
	ProtocolWebSocket Protocol = "websocket"
)

// TunnelState represents the tunnel connection state.
type TunnelState string

const (
	// StateConnecting means the tunnel is connecting.
	StateConnecting TunnelState = "connecting"
	// StateConnected means the tunnel is connected.
	StateConnected TunnelState = "connected"
	// StateReconnecting means the tunnel is reconnecting.
	StateReconnecting TunnelState = "reconnecting"
	// StateDisconnected means the tunnel is disconnected.
	StateDisconnected TunnelState = "disconnected"
	// StateClosed means the tunnel has been closed.
	StateClosed TunnelState = "closed"
	// StateError means the tunnel is in an error state.
	StateError TunnelState = "error"
)

// TunnelConfig contains configuration for creating a tunnel.
type TunnelConfig struct {
	// Protocol to use (default: HTTP)
	Protocol Protocol `json:"protocol,omitempty"`

	// LocalHost to forward to (default: 127.0.0.1)
	LocalHost string `json:"local_host,omitempty"`

	// LocalPort to forward to (required)
	LocalPort int `json:"local_port"`

	// Subdomain to request (optional)
	Subdomain string `json:"subdomain,omitempty"`

	// BasicAuth credentials (username -> password)
	BasicAuth map[string]string `json:"basic_auth,omitempty"`

	// IPAllow is a list of allowed CIDRs
	IPAllow []string `json:"ip_allow,omitempty"`

	// IPDeny is a list of denied CIDRs
	IPDeny []string `json:"ip_deny,omitempty"`

	// Headers to add to requests
	Headers map[string]string `json:"headers,omitempty"`

	// Inspect enables request inspection
	Inspect bool `json:"inspect"`

	// Metadata is custom key-value data
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// TunnelMetrics contains tunnel usage metrics.
type TunnelMetrics struct {
	RequestsTotal     uint64    `json:"requests_total"`
	BytesIn           uint64    `json:"bytes_in"`
	BytesOut          uint64    `json:"bytes_out"`
	ConnectionsActive uint32    `json:"connections_active"`
	LatencyAvgMs      float64   `json:"latency_avg_ms"`
	LatencyP99Ms      float64   `json:"latency_p99_ms"`
	ErrorsTotal       uint64    `json:"errors_total"`
	LastRequestAt     time.Time `json:"last_request_at,omitempty"`
}

// TunnelInfo contains information about an existing tunnel.
type TunnelInfo struct {
	ID           string                 `json:"id"`
	PublicURL    string                 `json:"public_url"`
	Protocol     Protocol               `json:"protocol"`
	LocalAddress string                 `json:"local_address"`
	State        TunnelState            `json:"state"`
	CreatedAt    time.Time              `json:"created_at"`
	Metrics      TunnelMetrics          `json:"metrics"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Tunnel represents an active tunnel connection.
type Tunnel struct {
	id        string
	publicURL string
	config    *TunnelConfig
	createdAt time.Time

	state   atomic.Value // TunnelState
	metrics atomic.Value // *TunnelMetrics

	closeCh   chan struct{}
	closeOnce sync.Once

	mu       sync.RWMutex
	handlers []func(TunnelState)
}

// newTunnel creates a new tunnel instance.
func newTunnel(id, publicURL string, config *TunnelConfig) *Tunnel {
	t := &Tunnel{
		id:        id,
		publicURL: publicURL,
		config:    config,
		createdAt: time.Now(),
		closeCh:   make(chan struct{}),
	}
	t.state.Store(StateConnecting)
	t.metrics.Store(&TunnelMetrics{})
	return t
}

// ID returns the tunnel ID.
func (t *Tunnel) ID() string {
	return t.id
}

// PublicURL returns the public URL for the tunnel.
func (t *Tunnel) PublicURL() string {
	return t.publicURL
}

// Config returns the tunnel configuration.
func (t *Tunnel) Config() *TunnelConfig {
	return t.config
}

// State returns the current tunnel state.
func (t *Tunnel) State() TunnelState {
	return t.state.Load().(TunnelState)
}

// Metrics returns the current metrics.
func (t *Tunnel) Metrics() *TunnelMetrics {
	return t.metrics.Load().(*TunnelMetrics)
}

// CreatedAt returns the creation time.
func (t *Tunnel) CreatedAt() time.Time {
	return t.createdAt
}

// Wait blocks until the tunnel is closed.
func (t *Tunnel) Wait() {
	<-t.closeCh
}

// WaitChan returns a channel that is closed when the tunnel closes.
func (t *Tunnel) WaitChan() <-chan struct{} {
	return t.closeCh
}

// Close closes the tunnel.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.state.Store(StateClosed)
		close(t.closeCh)
		t.notifyStateChange(StateClosed)
	})
	return nil
}

// OnStateChange registers a callback for state changes.
func (t *Tunnel) OnStateChange(fn func(TunnelState)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers = append(t.handlers, fn)
}

// setState updates the tunnel state.
func (t *Tunnel) setState(state TunnelState) {
	t.state.Store(state)
	t.notifyStateChange(state)
	if state == StateClosed {
		t.closeOnce.Do(func() {
			close(t.closeCh)
		})
	}
}

// notifyStateChange notifies all registered handlers.
func (t *Tunnel) notifyStateChange(state TunnelState) {
	t.mu.RLock()
	handlers := make([]func(TunnelState), len(t.handlers))
	copy(handlers, t.handlers)
	t.mu.RUnlock()

	for _, fn := range handlers {
		fn(state)
	}
}

// updateMetrics updates the tunnel metrics.
func (t *Tunnel) updateMetrics(metrics *TunnelMetrics) {
	t.metrics.Store(metrics)
}
