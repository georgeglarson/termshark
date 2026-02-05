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

Tests require tshark to be installed. Some tests use fixture pcap files. The CI workflow installs tshark before running tests. Build tag `tshark` gates integration tests that launch real tshark processes: `go test -tags tshark -v ./pkg/pcap/...`

## Tshark Capabilities Reference

This section documents tshark's full feature set to inform development. Items marked **[USED]** are wrapped by termshark; unmarked items are available but not yet exposed.

### Output Formats (`-T`)

| Format | Flag | Status |
|--------|------|--------|
| PDML (packet structure XML) | `-T pdml` | **[USED]** — packet detail tree |
| PSML (packet summary XML) | `-T psml` | **[USED]** — packet list |
| Hex dump | `-x` | **[USED]** — hex view |
| JSON | `-T json` | Available |
| JSON raw | `-T jsonraw` | Available |
| ElasticSearch | `-T ek` | Available |
| Tab-separated | `-T tabs` | Available |
| Custom fields | `-T fields -e <field>` | Available |
| Plain text | `-T text` | Available (default) |

### Stream Follow (`-z follow,<proto>,<mode>,<filter>`)

| Protocol | Status |
|----------|--------|
| TCP | **[USED]** — `pkg/streams/` |
| UDP | **[USED]** — `pkg/streams/` |
| TLS/SSL | Available |
| HTTP | Available |
| HTTP/2 | Available (substream support) |
| QUIC | Available (substream support) |
| DCCP | Available |

Output modes: `ascii`, `ebcdic`, `hex`, `raw`, `utf-8`, `yaml`.

### Conversations and Endpoints (`-z conv,<type>` / `-z endpoints,<type>`)

| Type | Conversations | Endpoints |
|------|--------------|-----------|
| Ethernet (`eth`) | **[USED]** | Available |
| IPv4 (`ip`) | **[USED]** | Available |
| IPv6 (`ipv6`) | **[USED]** | Available |
| TCP (`tcp`) | **[USED]** | Available |
| UDP (`udp`) | **[USED]** | Available |
| DCCP | Available | Available |
| SCTP | Available | Available |
| RSVP | Available | Available |

### Statistics (`-z`) — Not Yet Exposed

**I/O and Distribution:**
- `io,stat,<interval>[,<filter>]` — I/O statistics with time buckets, supports COUNT/SUM/MIN/MAX/AVG/LOAD
- `io,phs[,<filter>]` — Protocol hierarchy statistics (packet counts per protocol layer)
- `plen,tree` — Packet length distribution
- `ptype,tree` — Port type distribution

**Expert Info:**
- `expert[,<severity>][,<filter>]` — Expert info grouped by severity (error/warn/note/chat)

**Protocol-Specific:**
- `http,stat` / `http,tree` / `http_req,tree` / `http_srv,tree` — HTTP statistics and request/response distribution
- `dns,tree` — DNS query/response distribution
- `sip,stat` — SIP method and status code counts
- `rtp,streams` — RTP stream analysis (jitter, packet loss, max delta)
- `smb,srt` / `smb2,srt` — SMB/SMB2 service response time
- `credentials` — Extract credentials from FTP, HTTP, IMAP, POP, SMTP

**Service Response Time (SRT):**
- `dcerpc,srt,<uuid>,<ver>` / `diameter,srt` / `ncp,srt` / `rpc,srt,<prog>,<ver>` / `scsi,srt,<cmdset>` / `snmp,srt` — Protocol-specific response time analysis

**Network:**
- `hosts` — Hostname resolution statistics
- `ip_hosts,tree` / `ip_srcdst,tree` / `ip_ttl,tree` — IPv4 host/TTL analysis
- `dests,tree` — Destination address/protocol/port trees
- `flow,<name>,<mode>` — Data flow visualization (tcp/icmp/icmpv6)

**Cellular/Telecom:**
- `gsm_a` / `gsm_map,operation` / `mac-lte,stat` / `rlc-lte,stat` / `isup_msg,tree`

### Other tshark Features

**Capture control:**
- Ring buffers: `-b duration:N`, `-b filesize:N`, `-b files:N`, `-b packets:N`
- Stop conditions: `-a duration:N`, `-a filesize:N`, `-a packets:N`

**Dissection control:**
- Decode-As: `-d <layer>==<selector>,<protocol>` — **[USED]**
- `--disable-protocol` / `--enable-protocol` / `--only-protocols`
- `--disable-heuristic` / `--enable-heuristic`

**Name resolution (`-N`):**
- `d` DNS from packets, `g` geolocation, `m` MAC, `n` network, `t` transport ports, `v` VLAN
- `-n` disables all resolution — **[USED]** (conversations toggle)

**Timestamp formats (`-t`):**
- `a` absolute, `ad` with date, `d` delta, `dd` delta-displayed, `e` epoch, `r` relative (default), `u` UTC

**Export:**
- `--export-objects <proto>,<dir>` — Extract HTTP/SMB/etc. objects to files
- `--export-tls-session-keys <file>` — Export TLS session keys

**Decryption:**
- `-K <keytab>` — Kerberos keytab
- TLS decryption via preferences (`-o ssl.keylog_file:<path>`)

**Two-pass analysis:**
- `-2` enables features requiring future packet knowledge (proper reassembly stats, read filters via `-R`)

**Profiles:** `-C <profile>` — **[USED]**
**Color rules:** `--color` — **[USED]**

### Command Patterns Used by Termshark

```bash
# Packet list (PSML)
tshark -T psml -r <file> [-Y <filter>] [-o gui.column.format:...] -l [--color]

# Packet structure (PDML)
tshark -T pdml -r <file> [-Y <filter>] [--color]

# Follow stream
tshark -r <file> -q -z follow,<tcp|udp>,raw,<stream_index>

# Conversations
tshark -q -r <file> [-t a] [-n] -z conv,<type>[,<filter>]...

# Live capture (via dumpcap, fallback to tshark)
dumpcap -i <iface> -w <tmpfile> [-f <capture_filter>]
```
