"""NLAG tunnel management."""

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .exceptions import TunnelError


class TunnelState(Enum):
    """Tunnel connection states."""
    
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    DISCONNECTED = "disconnected"
    CLOSED = "closed"
    ERROR = "error"


class Protocol(Enum):
    """Supported tunnel protocols."""
    
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    UDP = "udp"
    GRPC = "grpc"
    WEBSOCKET = "websocket"


@dataclass
class TunnelConfig:
    """Configuration for creating a tunnel."""
    
    # Protocol to use
    protocol: Protocol = Protocol.HTTP
    
    # Local address to forward to
    local_host: str = "127.0.0.1"
    local_port: int = 8080
    
    # Optional subdomain request
    subdomain: Optional[str] = None
    
    # Basic auth configuration
    basic_auth: Optional[Dict[str, str]] = None
    
    # IP allowlist (CIDR notation)
    ip_allow: Optional[List[str]] = None
    
    # IP denylist (CIDR notation)
    ip_deny: Optional[List[str]] = None
    
    # Custom headers to add
    headers: Optional[Dict[str, str]] = None
    
    # Request inspection enabled
    inspect: bool = True
    
    # Custom metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API requests."""
        return {
            "protocol": self.protocol.value,
            "local_host": self.local_host,
            "local_port": self.local_port,
            "subdomain": self.subdomain,
            "basic_auth": self.basic_auth,
            "ip_allow": self.ip_allow,
            "ip_deny": self.ip_deny,
            "headers": self.headers,
            "inspect": self.inspect,
            "metadata": self.metadata,
        }


@dataclass
class TunnelMetrics:
    """Tunnel usage metrics."""
    
    requests_total: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    connections_active: int = 0
    latency_avg_ms: float = 0.0
    latency_p99_ms: float = 0.0
    errors_total: int = 0
    last_request_at: Optional[datetime] = None


class Tunnel:
    """
    Represents an active tunnel connection.
    
    Use the async context manager pattern:
    
        async with client.expose(port=8080) as tunnel:
            print(f"URL: {tunnel.public_url}")
            await tunnel.wait()
    """
    
    def __init__(
        self,
        tunnel_id: str,
        public_url: str,
        config: TunnelConfig,
        connection: Any,  # Internal connection object
    ):
        self._id = tunnel_id
        self._public_url = public_url
        self._config = config
        self._connection = connection
        self._state = TunnelState.CONNECTING
        self._metrics = TunnelMetrics()
        self._callbacks: Dict[str, List[Callable]] = {
            "request": [],
            "connect": [],
            "disconnect": [],
            "error": [],
        }
        self._close_event = asyncio.Event()
        self._created_at = datetime.utcnow()

    @property
    def id(self) -> str:
        """Unique tunnel identifier."""
        return self._id

    @property
    def public_url(self) -> str:
        """Public URL for accessing the tunnel."""
        return self._public_url

    @property
    def state(self) -> TunnelState:
        """Current tunnel state."""
        return self._state

    @property
    def metrics(self) -> TunnelMetrics:
        """Current tunnel metrics."""
        return self._metrics

    @property
    def config(self) -> TunnelConfig:
        """Tunnel configuration."""
        return self._config

    @property
    def created_at(self) -> datetime:
        """When the tunnel was created."""
        return self._created_at

    def on_request(self, callback: Callable) -> None:
        """Register a callback for incoming requests."""
        self._callbacks["request"].append(callback)

    def on_connect(self, callback: Callable) -> None:
        """Register a callback for connection events."""
        self._callbacks["connect"].append(callback)

    def on_disconnect(self, callback: Callable) -> None:
        """Register a callback for disconnection events."""
        self._callbacks["disconnect"].append(callback)

    def on_error(self, callback: Callable) -> None:
        """Register a callback for error events."""
        self._callbacks["error"].append(callback)

    async def wait(self) -> None:
        """Wait for the tunnel to be closed."""
        await self._close_event.wait()

    async def close(self) -> None:
        """Close the tunnel."""
        if self._state == TunnelState.CLOSED:
            return
            
        self._state = TunnelState.CLOSED
        
        # Close the underlying connection
        if self._connection:
            try:
                await self._connection.close()
            except Exception:
                pass
        
        self._close_event.set()

    async def refresh_metrics(self) -> TunnelMetrics:
        """Refresh and return current metrics."""
        if self._connection:
            try:
                data = await self._connection.get_metrics()
                self._metrics = TunnelMetrics(
                    requests_total=data.get("requests_total", 0),
                    bytes_in=data.get("bytes_in", 0),
                    bytes_out=data.get("bytes_out", 0),
                    connections_active=data.get("connections_active", 0),
                    latency_avg_ms=data.get("latency_avg_ms", 0.0),
                    latency_p99_ms=data.get("latency_p99_ms", 0.0),
                    errors_total=data.get("errors_total", 0),
                )
            except Exception:
                pass
        return self._metrics

    def __repr__(self) -> str:
        return f"Tunnel(id={self._id!r}, url={self._public_url!r}, state={self._state.value})"

    async def __aenter__(self) -> "Tunnel":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


@dataclass
class TunnelInfo:
    """Information about an existing tunnel."""
    
    id: str
    public_url: str
    protocol: Protocol
    local_address: str
    state: TunnelState
    created_at: datetime
    metrics: TunnelMetrics
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TunnelInfo":
        """Create from API response."""
        return cls(
            id=data["id"],
            public_url=data["public_url"],
            protocol=Protocol(data["protocol"]),
            local_address=data["local_address"],
            state=TunnelState(data["state"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            metrics=TunnelMetrics(
                requests_total=data.get("metrics", {}).get("requests_total", 0),
                bytes_in=data.get("metrics", {}).get("bytes_in", 0),
                bytes_out=data.get("metrics", {}).get("bytes_out", 0),
            ),
            metadata=data.get("metadata", {}),
        )
