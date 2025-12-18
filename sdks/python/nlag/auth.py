"""NLAG authentication utilities."""

import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from .exceptions import AuthenticationError


@dataclass
class Credentials:
    """User credentials for NLAG."""
    
    token: str
    user_id: str
    email: Optional[str] = None
    expires_at: Optional[datetime] = None
    refresh_token: Optional[str] = None

    def is_expired(self) -> bool:
        """Check if credentials are expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        return {
            "token": self.token,
            "user_id": self.user_id,
            "email": self.email,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "refresh_token": self.refresh_token,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Credentials":
        """Create from dictionary."""
        return cls(
            token=data["token"],
            user_id=data["user_id"],
            email=data.get("email"),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            refresh_token=data.get("refresh_token"),
        )


def get_credentials_path() -> Path:
    """Get the path to the credentials file."""
    # Check environment variable first
    if env_path := os.environ.get("NLAG_CREDENTIALS_PATH"):
        return Path(env_path)
    
    # Default to ~/.nlag/credentials.json
    return Path.home() / ".nlag" / "credentials.json"


def load_credentials() -> Optional[Credentials]:
    """
    Load credentials from the default location.
    
    Returns None if no credentials are found.
    """
    path = get_credentials_path()
    
    if not path.exists():
        return None
    
    try:
        with open(path) as f:
            data = json.load(f)
        return Credentials.from_dict(data)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise AuthenticationError(f"Invalid credentials file: {e}")


def save_credentials(credentials: Credentials) -> None:
    """Save credentials to the default location."""
    path = get_credentials_path()
    
    # Create directory if needed
    path.parent.mkdir(parents=True, exist_ok=True)
    
    # Set restrictive permissions
    with open(path, "w") as f:
        json.dump(credentials.to_dict(), f, indent=2)
    
    # Make file readable only by owner
    os.chmod(path, 0o600)


def clear_credentials() -> None:
    """Remove stored credentials."""
    path = get_credentials_path()
    if path.exists():
        path.unlink()


async def authenticate(
    email: str,
    password: str,
    server: str = "https://api.nlag.dev",
) -> Credentials:
    """
    Authenticate with the NLAG control plane.
    
    Args:
        email: User email address
        password: User password
        server: Control plane server URL
        
    Returns:
        Credentials object on success
        
    Raises:
        AuthenticationError: If authentication fails
    """
    import aiohttp
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f"{server}/api/v1/auth/login",
                json={"email": email, "password": password},
            ) as resp:
                if resp.status == 401:
                    raise AuthenticationError("Invalid email or password")
                if resp.status == 429:
                    raise AuthenticationError("Rate limit exceeded, try again later")
                if resp.status != 200:
                    raise AuthenticationError(f"Authentication failed: {resp.status}")
                
                data = await resp.json()
                
                credentials = Credentials(
                    token=data["token"],
                    user_id=data["user_id"],
                    email=email,
                    expires_at=(
                        datetime.fromisoformat(data["expires_at"])
                        if data.get("expires_at")
                        else None
                    ),
                    refresh_token=data.get("refresh_token"),
                )
                
                # Save credentials
                save_credentials(credentials)
                
                return credentials
                
        except aiohttp.ClientError as e:
            raise AuthenticationError(f"Connection error: {e}")


async def authenticate_with_token(token: str) -> Credentials:
    """
    Authenticate using an API token.
    
    Args:
        token: API token
        
    Returns:
        Credentials object
    """
    credentials = Credentials(
        token=token,
        user_id="api-token",
    )
    save_credentials(credentials)
    return credentials


async def refresh_token(credentials: Credentials, server: str = "https://api.nlag.dev") -> Credentials:
    """
    Refresh an expired token.
    
    Args:
        credentials: Current credentials with refresh token
        server: Control plane server URL
        
    Returns:
        New credentials
        
    Raises:
        AuthenticationError: If refresh fails
    """
    import aiohttp
    
    if not credentials.refresh_token:
        raise AuthenticationError("No refresh token available")
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                f"{server}/api/v1/auth/refresh",
                json={"refresh_token": credentials.refresh_token},
            ) as resp:
                if resp.status != 200:
                    raise AuthenticationError("Token refresh failed")
                
                data = await resp.json()
                
                new_credentials = Credentials(
                    token=data["token"],
                    user_id=credentials.user_id,
                    email=credentials.email,
                    expires_at=(
                        datetime.fromisoformat(data["expires_at"])
                        if data.get("expires_at")
                        else None
                    ),
                    refresh_token=data.get("refresh_token", credentials.refresh_token),
                )
                
                save_credentials(new_credentials)
                return new_credentials
                
        except aiohttp.ClientError as e:
            raise AuthenticationError(f"Connection error: {e}")
