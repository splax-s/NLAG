"""NLAG client for managing tunnels."""

import asyncio
import ssl
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .auth import Credentials, load_credentials
from .exceptions import AuthenticationError, ConfigurationError, ConnectionError, TunnelError
from .tunnel import Protocol, Tunnel, TunnelConfig, TunnelInfo


@dataclass
class ClientConfig:
    """Configuration for the NLAG client."""
    
    # Edge server address
    edge_url: str = "localhost:4443"
    
    # Control plane server
    control_url: str = "https://api.nlag.dev"
    
    # Skip TLS verification (DANGEROUS - development only)
    insecure: bool = False
    
    # Connection timeout in seconds
    connect_timeout: float = 30.0
    
    # Reconnect settings
    reconnect_enabled: bool = True
    reconnect_delay: float = 1.0
    max_reconnect_delay: float = 30.0
    max_reconnect_attempts: int = 0  # 0 = infinite
    
    # Credentials (loaded automatically if not provided)
    credentials: Optional[Credentials] = None
    
    # Custom CA certificate path
    ca_cert: Optional[str] = None
    
    # Additional metadata to include with tunnels
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        """Validate configuration."""
        if not self.edge_url:
            raise ConfigurationError("edge_url is required", field="edge_url")
        if self.connect_timeout <= 0:
            raise ConfigurationError("connect_timeout must be positive", field="connect_timeout")
        if self.reconnect_delay <= 0:
            raise ConfigurationError("reconnect_delay must be positive", field="reconnect_delay")


class Client:
    """
    NLAG client for creating and managing tunnels.
    
    Usage with async context manager (recommended):
    
        async with Client() as client:
            tunnel = await client.expose(protocol="http", local_port=8080)
            print(f"URL: {tunnel.public_url}")
            await tunnel.wait()
    
    Manual usage:
    
        client = Client()
        await client.connect()
        try:
            tunnel = await client.expose(protocol="http", local_port=8080)
            await tunnel.wait()
        finally:
            await client.close()
    """
    
    def __init__(self, config: Optional[ClientConfig] = None, **kwargs):
        """
        Initialize the client.
        
        Args:
            config: Client configuration object
            **kwargs: Override individual config options
        """
        self._config = config or ClientConfig()
        
        # Apply any overrides
        for key, value in kwargs.items():
            if hasattr(self._config, key):
                setattr(self._config, key, value)
            else:
                raise ConfigurationError(f"Unknown configuration option: {key}")
        
        self._config.validate()
        
        self._connected = False
        self._tunnels: Dict[str, Tunnel] = {}
        self._connection = None
        self._credentials = self._config.credentials

    @property
    def connected(self) -> bool:
        """Whether the client is connected to the edge server."""
        return self._connected

    @property
    def tunnels(self) -> List[Tunnel]:
        """List of active tunnels."""
        return list(self._tunnels.values())

    async def connect(self) -> None:
        """
        Connect to the edge server.
        
        This is called automatically when using the async context manager.
        """
        if self._connected:
            return
        
        # Load credentials if not provided
        if not self._credentials:
            self._credentials = load_credentials()
            if not self._credentials:
                raise AuthenticationError(
                    "No credentials found. Run `nlag login` or provide credentials."
                )
        
        # Check if credentials are expired
        if self._credentials.is_expired():
            raise AuthenticationError("Credentials have expired. Please log in again.")
        
        try:
            # Create QUIC connection to edge server
            self._connection = await self._create_connection()
            self._connected = True
        except Exception as e:
            raise ConnectionError(f"Failed to connect to edge server: {e}")

    async def close(self) -> None:
        """
        Close the client and all tunnels.
        
        This is called automatically when using the async context manager.
        """
        # Close all tunnels
        for tunnel in list(self._tunnels.values()):
            try:
                await tunnel.close()
            except Exception:
                pass
        
        self._tunnels.clear()
        
        # Close connection
        if self._connection:
            try:
                await self._connection.close()
            except Exception:
                pass
            self._connection = None
        
        self._connected = False

    async def expose(
        self,
        local_port: int,
        protocol: Union[str, Protocol] = Protocol.HTTP,
        local_host: str = "127.0.0.1",
        subdomain: Optional[str] = None,
        **kwargs,
    ) -> Tunnel:
        """
        Expose a local service through a tunnel.
        
        Args:
            local_port: Local port to forward traffic to
            protocol: Protocol to use (http, https, tcp, udp, grpc, websocket)
            local_host: Local host to forward to (default: 127.0.0.1)
            subdomain: Request a specific subdomain
            **kwargs: Additional tunnel configuration options
            
        Returns:
            Tunnel object representing the active tunnel
            
        Raises:
            TunnelError: If tunnel creation fails
            ConnectionError: If not connected
        """
        if not self._connected:
            await self.connect()
        
        # Convert string protocol to enum
        if isinstance(protocol, str):
            try:
                protocol = Protocol(protocol.lower())
            except ValueError:
                raise TunnelError(f"Invalid protocol: {protocol}")
        
        # Build config
        config = TunnelConfig(
            protocol=protocol,
            local_host=local_host,
            local_port=local_port,
            subdomain=subdomain,
            **kwargs,
        )
        
        # Create tunnel through connection
        try:
            tunnel_data = await self._connection.create_tunnel(config.to_dict())
            
            tunnel = Tunnel(
                tunnel_id=tunnel_data["id"],
                public_url=tunnel_data["public_url"],
                config=config,
                connection=self._connection,
            )
            
            self._tunnels[tunnel.id] = tunnel
            return tunnel
            
        except Exception as e:
            raise TunnelError(f"Failed to create tunnel: {e}")

    async def expose_http(self, local_port: int, **kwargs) -> Tunnel:
        """Convenience method to expose an HTTP service."""
        return await self.expose(local_port, protocol=Protocol.HTTP, **kwargs)

    async def expose_tcp(self, local_port: int, **kwargs) -> Tunnel:
        """Convenience method to expose a TCP service."""
        return await self.expose(local_port, protocol=Protocol.TCP, **kwargs)

    async def expose_udp(self, local_port: int, **kwargs) -> Tunnel:
        """Convenience method to expose a UDP service."""
        return await self.expose(local_port, protocol=Protocol.UDP, **kwargs)

    async def expose_grpc(self, local_port: int, **kwargs) -> Tunnel:
        """Convenience method to expose a gRPC service."""
        return await self.expose(local_port, protocol=Protocol.GRPC, **kwargs)

    async def list_tunnels(self) -> List[TunnelInfo]:
        """
        List all tunnels for the authenticated user.
        
        Returns:
            List of TunnelInfo objects
        """
        if not self._connected:
            await self.connect()
        
        try:
            tunnels_data = await self._connection.list_tunnels()
            return [TunnelInfo.from_dict(t) for t in tunnels_data]
        except Exception as e:
            raise TunnelError(f"Failed to list tunnels: {e}")

    async def get_tunnel(self, tunnel_id: str) -> Optional[Tunnel]:
        """Get a tunnel by ID."""
        return self._tunnels.get(tunnel_id)

    async def close_tunnel(self, tunnel_id: str) -> None:
        """Close a specific tunnel."""
        if tunnel := self._tunnels.get(tunnel_id):
            await tunnel.close()
            del self._tunnels[tunnel_id]

    async def _create_connection(self):
        """Create a connection to the edge server."""
        # This is a placeholder - actual implementation would use
        # aioquic or similar for QUIC connections
        from .transport import QUICConnection
        
        return await QUICConnection.connect(
            host=self._config.edge_url,
            token=self._credentials.token if self._credentials else None,
            insecure=self._config.insecure,
            ca_cert=self._config.ca_cert,
            timeout=self._config.connect_timeout,
        )

    def __repr__(self) -> str:
        status = "connected" if self._connected else "disconnected"
        return f"Client(edge={self._config.edge_url!r}, status={status}, tunnels={len(self._tunnels)})"

    async def __aenter__(self) -> "Client":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()


# Convenience function for quick tunnel creation
async def expose(
    local_port: int,
    protocol: str = "http",
    subdomain: Optional[str] = None,
    edge_url: str = "localhost:4443",
    **kwargs,
) -> Tunnel:
    """
    Quick function to expose a local service.
    
    This creates a client, connects, and creates a tunnel in one call.
    The returned tunnel should be used with async context manager:
    
        async with expose(8080, subdomain="myapp") as tunnel:
            print(f"URL: {tunnel.public_url}")
            await tunnel.wait()
    
    Args:
        local_port: Local port to forward
        protocol: Protocol (http, https, tcp, etc.)
        subdomain: Optional subdomain request
        edge_url: Edge server address
        **kwargs: Additional tunnel options
        
    Returns:
        Tunnel object
    """
    client = Client(edge_url=edge_url)
    await client.connect()
    return await client.expose(local_port, protocol=protocol, subdomain=subdomain, **kwargs)
