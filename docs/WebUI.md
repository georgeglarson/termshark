# Termshark Web UI

The web UI provides a browser-based interface for packet analysis, useful for:
- Remote access to termshark running on a server
- Collaborative analysis with session sharing
- Live packet capture from web browser
- Enhanced visualization (graphs, charts)
- Easier copy/paste and text selection
- Mobile device access

## Requirements

- **sharkd**: The Wireshark daemon. Usually included with Wireshark.
  - Debian/Ubuntu: `sudo apt install wireshark-common`
  - macOS: Included with Wireshark.app
  - Windows: Build from source or use WSL

- **For live capture**: Root/sudo access or appropriate capabilities

## Starting the Web UI

### Basic Usage

```bash
# Load a pcap file
termshark --web -r capture.pcap

# Custom address (allow remote access)
termshark --web --web-addr 0.0.0.0:8080 -r capture.pcap

# Without a file (can load via UI or start capture)
termshark --web
```

### Live Capture

```bash
# Start with live capture on interface
termshark --web -i eth0

# With capture filter
termshark --web -i eth0 -f "port 80"
```

### Multi-Session Mode

Multi-session mode allows multiple users to create, join, and share analysis sessions:

```bash
# Enable multi-session mode
termshark --web --web-sessions

# Create an initial session with a name
termshark --web --web-sessions --session-name "My Analysis" -r capture.pcap

# Start with live capture in a named session
sudo termshark --web --web-sessions --session-name "Live Capture" -i eth0
```

## Interface Overview

### Header
- **Connection status**: Shows WebSocket connection state
- **Session info**: Displays current session name (in multi-session mode)
- **Sessions button**: Opens session picker (multi-session mode only)

### Controls
- **Filter input**: Enter Wireshark display filters (e.g., `tcp.port == 80`)
- **Apply button**: Apply the current filter
- **Capture controls**: Start/stop live capture (when supported)
  - Interface selector dropdown
  - Start/Stop capture buttons
  - Capture status indicator
- **File input**: Load a local pcap file (requires server-side path)

### Packet List
- Click a row to select it
- Use j/k or arrow keys to navigate
- Selected packet details appear below
- Auto-refreshes during live capture

### Packet Details
- **Tree view**: Expandable protocol tree
- **Hex view**: Raw bytes with ASCII

## Session Sharing

In multi-session mode, multiple users can collaborate:

1. **Create a session**: Enter a name and click "Create Session"
2. **Join a session**: Click on an existing session to join
3. **Share the URL**: Other users can access the same server and join your session
4. **View session info**: See how many clients are connected, packet count, etc.

### Session Features
- Real-time state synchronization across clients
- Independent display filters per client
- Shared packet data and analysis
- Session persistence until deleted

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `j` or `↓` | Select next packet |
| `k` or `↑` | Select previous packet |
| `/` | Focus filter input |
| `Escape` | Unfocus filter input / Close modal |

## Architecture

The web UI uses a three-tier architecture:

```
Browser <--WebSocket--> Go Server <--Unix Socket--> sharkd
```

1. **Browser**: Static HTML/JS/CSS served by Go
2. **Go Server**: Proxies JSON-RPC between browser and sharkd
3. **sharkd**: Wireshark's daemon providing packet analysis

### Multi-Session Architecture

```
                    ┌─── Session 1 ─── Manager ─── sharkd
Browser 1 ──┐      │
Browser 2 ──┼─ Go Server ─── Registry
Browser 3 ──┘      │
                    └─── Session 2 ─── Manager ─── sharkd
```

Each session has its own state manager and sharkd backend, allowing isolated analysis.

## API Reference

The web UI uses JSON-RPC 2.0 over WebSocket. Key methods:

### Session Management (multi-session mode)
- `sessions.list`: List all available sessions
- `sessions.create`: Create a new session
- `sessions.join`: Join an existing session
- `sessions.leave`: Leave current session
- `sessions.info`: Get session details
- `sessions.delete`: Delete a session

### Packet Analysis
- `status`: Get current status (packet count, columns, etc.)
- `load`: Load a pcap file
- `frames`: Get packet summaries
- `frame`: Get packet details
- `check`: Validate a display filter
- `setfilter`: Apply a display filter

### Capture Control
- `listInterfaces`: List available network interfaces
- `startCapture`: Start live capture
- `stopCapture`: Stop live capture
- `isCapturing`: Check capture status

## Troubleshooting

### "sharkd not found"
Ensure sharkd is in your PATH:
```bash
which sharkd
# If not found, install wireshark-common or build from source
```

### Connection refused
Check if the server started successfully and the port is available.

### No packets displayed
Verify the pcap file path is accessible from the server's perspective.

### Capture controls not showing
- Ensure you have permission to enumerate network interfaces
- Run with sudo for full capture support
- Check that dumpcap is properly configured

### Session not visible to other users
- Ensure all users are connecting to the same server address
- Verify `--web-sessions` flag is enabled
- Check firewall settings if accessing remotely

## Security Considerations

- The web UI has no authentication by default
- Use `127.0.0.1` (default) to restrict to local access
- For remote access, use a reverse proxy with authentication
- Live capture requires elevated privileges
- Consider network segmentation for sensitive traffic analysis
