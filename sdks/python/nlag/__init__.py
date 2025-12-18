"""
NLAG Python SDK - Expose local services through secure tunnels

This SDK provides a programmatic interface to the NLAG tunneling platform,
allowing you to create and manage tunnels from Python applications.

Example usage:
    from nlag import Client, TunnelConfig

    async with Client() as client:
        tunnel = await client.expose(
            protocol="http",
            local_port=8080,
            subdomain="myapp"
        )
        print(f"Tunnel URL: {tunnel.public_url}")
        await tunnel.wait()
"""

__version__ = "0.1.0"

from .client import Client, ClientConfig
from .tunnel import Tunnel, TunnelConfig, TunnelState
from .auth import authenticate, load_credentials, Credentials
from .exceptions import (
    NlagError,
    AuthenticationError,
    ConnectionError,
    TunnelError,
    ConfigurationError,
)

__all__ = [
    # Client
    "Client",
    "ClientConfig",
    # Tunnel
    "Tunnel",
    "TunnelConfig",
    "TunnelState",
    # Auth
    "authenticate",
    "load_credentials",
    "Credentials",
    # Exceptions
    "NlagError",
    "AuthenticationError",
    "ConnectionError",
    "TunnelError",
    "ConfigurationError",
]
