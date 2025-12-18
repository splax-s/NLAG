# NLAG Tunnels - VS Code Extension

Create and manage NLAG tunnels directly from Visual Studio Code.

## Features

- **Quick Expose** - Expose ports with a single keyboard shortcut (Ctrl+Shift+E / Cmd+Shift+E)
- **Sidebar Panel** - View and manage all active tunnels
- **Protocol Support** - HTTP, HTTPS, TCP, UDP, gRPC, WebSocket
- **Auto-Expose on Debug** - Automatically create tunnels when starting debug sessions
- **Copy URLs** - One-click URL copying to clipboard
- **Inspector Integration** - Open request inspector directly from VS Code

## Installation

### From VSIX

```bash
code --install-extension nlag-tunnels-0.1.0.vsix
```

### From Source

```bash
cd vscode-extension
npm install
npm run compile
```

Then press F5 in VS Code to launch the Extension Development Host.

## Usage

### Quick Start

1. Open the Command Palette (Ctrl+Shift+P / Cmd+Shift+P)
2. Type "NLAG: Login" and authenticate
3. Type "NLAG: Expose Port" to create a tunnel

### Commands

| Command | Keybinding | Description |
|---------|------------|-------------|
| NLAG: Expose Port | | Create a tunnel with full options |
| NLAG: Quick Expose | Ctrl+Shift+E | Quick tunnel creation |
| NLAG: List Tunnels | | Show all active tunnels |
| NLAG: Close Tunnel | | Close a specific tunnel |
| NLAG: Close All Tunnels | | Close all tunnels |
| NLAG: Open Inspector | | Open request inspector |
| NLAG: Copy URL | | Copy tunnel URL to clipboard |
| NLAG: Login | | Authenticate with NLAG |
| NLAG: Logout | | Sign out |

### Sidebar

The NLAG Tunnels sidebar shows all active tunnels with:
- Public URL
- Local port mapping
- Protocol indicator
- Connection state

Right-click a tunnel for quick actions:
- Copy URL
- Open Inspector
- Close Tunnel

### Configuration

Open Settings (Ctrl+,) and search for "NLAG" to configure:

| Setting | Default | Description |
|---------|---------|-------------|
| `nlag.apiUrl` | `https://api.nlag.dev` | API endpoint |
| `nlag.edgeUrl` | `wss://connect.nlag.dev` | Edge server |
| `nlag.region` | | Preferred region |
| `nlag.defaultProtocol` | `http` | Default protocol |
| `nlag.showStatusBarItem` | `true` | Show status bar item |
| `nlag.autoExposeOnDebug` | `false` | Auto-expose on debug |
| `nlag.debugPort` | `3000` | Port for auto-expose |

### Auto-Expose on Debug

Enable automatic tunnel creation when starting debug sessions:

1. Set `nlag.autoExposeOnDebug` to `true`
2. Set `nlag.debugPort` to your dev server port
3. Start debugging - a tunnel is created automatically

## Development

### Building

```bash
npm install
npm run compile
```

### Testing

```bash
npm run test
```

### Packaging

```bash
npm run package
```

This creates `nlag-tunnels-0.1.0.vsix`.

## Requirements

- VS Code 1.85.0 or higher
- NLAG account (free or paid)

## License

MIT
