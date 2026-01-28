# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Termshark is a terminal user-interface for tshark (Wireshark's CLI tool). It provides interactive network packet analysis from the terminal, allowing users to read pcap files, capture live traffic, apply display filters, and inspect TCP/UDP streams.

**Runtime dependency:** `tshark` must be in PATH (version 1.10.2+).

## Build and Test Commands

```bash
# Build all packages
go build -v ./...

# Build the main binary
go build -v ./cmd/termshark

# Run all tests (requires tshark installed)
go test -v ./...

# Run tests for a specific package
go test -v ./pkg/pcap/...
go test -v ./widgets/filter/...

# Run a single test
go test -v ./pkg/streams/... -run TestFollowParser

# Install locally
go install ./cmd/termshark
```

## Architecture

### Core Packages (`pkg/`)

| Package | Purpose |
|---------|---------|
| `pcap` | PCAP file loading and live capture via tshark. Contains `Loader` which manages packet data streaming. |
| `streams` | TCP/UDP stream reassembly. Uses a PEG-generated parser (`follow.peg` -> `follow.go`). |
| `pdmltree` | PDML (Protocol Description Markup Language) tree model for packet structure display. |
| `psmlmodel` | PSML model for packet summary list. |
| `shark` | Wireshark configuration parsing and column format handling. |
| `convs` | Network conversation tracking (Ethernet, IPv4, IPv6, TCP, UDP). |
| `fields` | Field type definitions and management for display columns. |
| `theme` | Color theme loading from TOML files in `assets/themes/`. |

### UI Layer (`ui/`)

- `ui.go` - Main UI orchestration: packet list, structure tree, hex dump, dialogs
- `streamui.go` - TCP/UDP stream visualization
- `convsui.go` - Network conversations view
- `searchby*.go` - Various search implementations (filter, bytes, structure)

### Widgets (`widgets/`)

Custom TUI widgets built on gowid/tcell:
- `filter/` - Display filter input with validation and autocomplete
- `hexdumper2/` - Hex dump display
- `minibuffer/` - Command input
- `search/` - Search widget
- `wormhole/` - Data transfer via magic wormhole

### Configuration (`configs/profiles/`)

Viper-based profile management. TOML configuration files stored in XDG-compliant directories.

## Data Flow

1. User provides pcap file or live interface
2. `pkg/pcap/cmds.go` builds tshark command with appropriate flags
3. tshark outputs PDML/PSML XML which is parsed by `pkg/pdmltree` and `pkg/psmlmodel`
4. Parsed data is cached in LRU caches and rendered via gowid widgets
5. User interactions trigger filter validation and data reloading

## Key Patterns

**Goroutine coordination:** A centralized `lifecycle.Tracker` manages all goroutines via `termshark.Go()`. The tracker provides both a WaitGroup for synchronization and a context for shutdown signaling.

**Command execution:** All tshark/dumpcap commands use `exec.Command()` with array arguments (never shell strings) to prevent injection.

**Widget composition:** UI is built by composing gowid primitives (pile, columns, holder, etc.) with custom widgets.

## Testing Notes

Tests require tshark to be installed. Some tests use fixture pcap files. The CI workflow installs tshark before running tests.
