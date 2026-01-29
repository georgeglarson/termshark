# Termshark Web UI

The web UI provides a browser-based interface for packet analysis, useful for:
- Remote access to termshark running on a server
- Enhanced visualization (graphs, charts)
- Easier copy/paste and text selection
- Mobile device access

## Requirements

- **sharkd**: The Wireshark daemon. Usually included with Wireshark.
  - Debian/Ubuntu: `sudo apt install wireshark-common`
  - macOS: Included with Wireshark.app
  - Windows: Build from source or use WSL

## Starting the Web UI

```bash
# Basic usage
termshark --web -r capture.pcap

# Custom address (allow remote access)
termshark --web --web-addr 0.0.0.0:8080 -r capture.pcap

# Without a file (load via UI later)
termshark --web
```

## Interface Overview

### Header
- Shows connection status
- Displays loaded file info

### Controls
- **Filter input**: Enter Wireshark display filters (e.g., `tcp.port == 80`)
- **Apply button**: Apply the current filter
- **File input**: Load a local pcap file (requires server-side path)

### Packet List
- Click a row to select it
- Use j/k or arrow keys to navigate
- Selected packet details appear below

### Packet Details
- **Tree view**: Expandable protocol tree
- **Hex view**: Raw bytes with ASCII

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `j` or `↓` | Select next packet |
| `k` or `↑` | Select previous packet |
| `/` | Focus filter input |
| `Escape` | Unfocus filter input |

## Architecture

The web UI uses a three-tier architecture:

```
Browser <--WebSocket--> Go Server <--Unix Socket--> sharkd
```

1. **Browser**: Static HTML/JS/CSS served by Go
2. **Go Server**: Proxies JSON-RPC between browser and sharkd
3. **sharkd**: Wireshark's daemon providing packet analysis

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

## Limitations

- File upload requires server-side file path
- No live capture support yet
- Limited compared to terminal UI
